# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Send an IKEv2 IKE_SA_INIT and read what the responder selected.

Packet construction lives in ``_packet``; this module owns the exchange and the
parsing of what comes back.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass

from qureddy.scanners.ike._packet import (
    _ADDKE_SWEEP,
    _BASE_TRANSFORMS,
    _EXCHANGE_SA_INIT,
    _FLAG_RESPONSE,
    _HEADER_LEN,
    _KE_SWEEP,
    _NAMES_ENCR,
    _NAMES_INTEG,
    _NAMES_KE,
    _NAMES_PRF,
    _NON_ESP_MARKER,
    _NOTIFY_GROUP_LEN,
    _NOTIFY_HEADER_LEN,
    _NOTIFY_INVALID_KE,
    _NOTIFY_NO_PROPOSAL,
    _P_NOTIFY,
    _P_SA,
    _PAYLOAD_HEADER_LEN,
    _PORT_NAT_T,
    _PROPOSAL_HEADER_LEN,
    _T_ADDKE1,
    _T_ADDKE_RANGE,
    _T_ENCR,
    _T_INTEG,
    _T_KE,
    _T_PRF,
    _TRANSFORM_LEN,
    _TRANSFORM_WITH_ATTR_LEN,
    _VERSION_2_0,
    available_methods,
    build_sa_init,
)
from qureddy.scanners.ike.parser import ParsedIKEResponse
from qureddy.scanners.ike.types import IKEMode, IKEParseStatus

__all__ = ["LocalProbeError", "NativeProbe", "available_methods", "probe", "sweep"]


@dataclass(frozen=True, slots=True)
class NativeProbe:
    """One IKE_SA_INIT exchange and what the responder did with it."""

    key_exchange: int
    additional_key_exchange: int | None
    response: ParsedIKEResponse
    responder_spi: str | None = None
    #: Set when the responder echoed a Transform Type 5, which is the only
    #: positive evidence of RFC 9370 support.
    additional_accepted: int | None = None
    #: Status notifications carried in a successful response. RFC 9242's
    #: INTERMEDIATE_EXCHANGE_SUPPORTED decides whether RFC 9370 is reachable at
    #: all, so dropping it would lose a post-quantum fact the exchange proved.
    status_notifies: tuple[int, ...] = ()


def _walk_transforms(
    data: bytes,
    offset: int,
    encr: list[str],
    prf: list[str],
    integ: list[str],
    groups: list[tuple[int, str]],
    found: dict[int, int],
) -> None:
    """Record the transforms a responder selected, by type.

    Split from the parser so each has one job: this one advances through a
    length-delimited structure that an adversary controls, and never trusts a
    declared length to advance the cursor.
    """
    *_, count = struct.unpack(
        "!BBHBBBB", data[offset + _PAYLOAD_HEADER_LEN : offset + _PROPOSAL_HEADER_LEN]
    )
    cursor = offset + _PROPOSAL_HEADER_LEN
    for _ in range(count):
        if cursor + _TRANSFORM_LEN > len(data):
            return
        _, _, tlen = struct.unpack("!BBH", data[cursor : cursor + _PAYLOAD_HEADER_LEN])
        t_type, _, t_id = struct.unpack(
            "!BBH", data[cursor + _PAYLOAD_HEADER_LEN : cursor + _TRANSFORM_LEN]
        )
        bits = (
            struct.unpack("!H", data[cursor + 10 : cursor + _TRANSFORM_WITH_ATTR_LEN])[0]
            if tlen >= _TRANSFORM_WITH_ATTR_LEN
            else None
        )
        if t_type == _T_ENCR:
            name = _NAMES_ENCR.get(t_id, str(t_id))
            encr.append(f"{name}-{bits}" if bits else name)
        elif t_type == _T_PRF:
            prf.append(_NAMES_PRF.get(t_id, str(t_id)))
        elif t_type == _T_INTEG:
            integ.append(_NAMES_INTEG.get(t_id, str(t_id)))
        elif t_type == _T_KE:
            groups.append((t_id, _NAMES_KE.get(t_id, str(t_id))))
        elif t_type in _T_ADDKE_RANGE:
            found[t_type] = t_id
        cursor += max(tlen, _TRANSFORM_LEN)


def _unanswered(key_exchange: int, additional: int | None) -> NativeProbe:
    """Record a probe nothing valid came back for."""
    return NativeProbe(
        key_exchange,
        additional,
        ParsedIKEResponse(mode=IKEMode.IKEV2, status=IKEParseStatus.NO_RESPONSE),
    )


def _is_bound(
    init_spi: bytes,
    version: int,
    exchange: int,
    flags: int,
    message_id: int,
    sent_spi: bytes | None,
) -> bool:
    """Confirm a datagram answers the request that was sent.

    UDP accepts a datagram from anyone, so a reply whose initiator SPI, version,
    exchange type or message ID differs from what was sent is another party's
    traffic or a spoof. Crediting it would attribute someone else's posture to
    this target.
    """
    return bool(
        (sent_spi is None or init_spi == sent_spi)
        and version == _VERSION_2_0
        and exchange == _EXCHANGE_SA_INIT
        and message_id == 0
        and flags & _FLAG_RESPONSE
    )


def _collect_notify(data: bytes, offset: int, notifies: list[int]) -> None:
    """Record a status notification carried alongside a successful selection.

    A notify in an accepted response is an advertisement rather than a refusal,
    which is why it is collected here instead of ending the parse.
    """
    if offset + _NOTIFY_HEADER_LEN > len(data):
        return
    notifies.append(struct.unpack("!BBHBBH", data[offset : offset + _NOTIFY_HEADER_LEN])[5])


def _established(spi: bytes, groups: list[tuple[int, str]]) -> bool:
    """Decide whether the responder actually selected a proposal.

    Requires both a non-zero responder SPI and a key exchange method echoed
    back. The RESPONSE flag alone is not sufficient: a bare header, a truncated
    notify or a corrupted datagram would otherwise be recorded as a negotiated
    SA, the same offered-to-negotiated promotion the engine forbids elsewhere.
    """
    return spi != b"\x00" * 8 and bool(groups)


def _notify_probe(data: bytes, key_exchange: int, additional: int | None) -> NativeProbe:
    """Read a notify response.

    An INVALID_KE_PAYLOAD carries the group the responder accepts, so the
    refusal names its own remedy and the caller can follow it rather than stop.
    """
    _, _, plen, _, _, kind = struct.unpack(
        "!BBHBBH", data[_HEADER_LEN : _HEADER_LEN + _NOTIFY_HEADER_LEN]
    )
    payload = data[_HEADER_LEN + _NOTIFY_HEADER_LEN : _HEADER_LEN + plen]
    note = {
        _NOTIFY_INVALID_KE: "INVALID_KE_PAYLOAD",
        _NOTIFY_NO_PROPOSAL: "NO_PROPOSAL_CHOSEN",
    }.get(kind, f"NOTIFY_{kind}")
    if kind == _NOTIFY_INVALID_KE and len(payload) >= _NOTIFY_GROUP_LEN:
        expected = struct.unpack("!H", payload[:_NOTIFY_GROUP_LEN])[0]
        note = f"{note}:expects_group_{expected}"
    return NativeProbe(
        key_exchange,
        additional,
        ParsedIKEResponse(
            mode=IKEMode.IKEV2,
            status=IKEParseStatus.REJECTED,
            responder_notify=note,
        ),
    )


@dataclass(frozen=True, slots=True)
class _Selection:
    """What a successful response carried, grouped by transform type."""

    encryption: tuple[str, ...] = ()
    prf: tuple[str, ...] = ()
    integrity: tuple[str, ...] = ()
    groups: tuple[tuple[int, str], ...] = ()
    additional: dict[int, int] | None = None
    notifies: tuple[int, ...] = ()


def _walk_payloads(data: bytes, first_payload: int) -> _Selection:
    """Walk the payload chain of a successful response.

    Each length is declared by the peer, so the cursor advances only on a
    length that is both at least a header and inside the datagram. Without that
    pair of checks a declared zero would never advance and the walk would spin.
    """
    encr: list[str] = []
    prf: list[str] = []
    integ: list[str] = []
    groups: list[tuple[int, str]] = []
    found: dict[int, int] = {}
    notifies: list[int] = []
    offset, current = _HEADER_LEN, first_payload
    while current and offset + _PAYLOAD_HEADER_LEN <= len(data):
        nxt_p, _, plen = struct.unpack("!BBH", data[offset : offset + 4])
        if plen < _PAYLOAD_HEADER_LEN or offset + plen > len(data):
            break
        if current == _P_NOTIFY:
            _collect_notify(data, offset, notifies)
        if current == _P_SA and offset + _PROPOSAL_HEADER_LEN <= len(data):
            _walk_transforms(data, offset, encr, prf, integ, groups, found)
        offset += plen
        current = nxt_p
    return _Selection(tuple(encr), tuple(prf), tuple(integ), tuple(groups), found, tuple(notifies))


def _parse(
    data: bytes, key_exchange: int, additional: int | None, sent_spi: bytes | None = None
) -> NativeProbe:
    """Read the responder's selection, or the notify explaining the refusal."""
    if len(data) < _HEADER_LEN:
        return NativeProbe(
            key_exchange,
            additional,
            ParsedIKEResponse(mode=IKEMode.IKEV2, status=IKEParseStatus.NO_RESPONSE),
        )
    init_spi, spi, nxt, ver, exch, flags, msg_id, _ = struct.unpack(
        "!8s8sBBBBII", data[:_HEADER_LEN]
    )
    if not _is_bound(init_spi, ver, exch, flags, msg_id, sent_spi):
        return _unanswered(key_exchange, additional)
    if nxt == _P_NOTIFY and len(data) >= _HEADER_LEN + _NOTIFY_HEADER_LEN:
        return _notify_probe(data, key_exchange, additional)

    selection = _walk_payloads(data, nxt)

    established = _established(spi, list(selection.groups))
    return NativeProbe(
        key_exchange=key_exchange,
        additional_key_exchange=additional,
        responder_spi=spi.hex() if established else None,
        additional_accepted=(selection.additional or {}).get(_T_ADDKE1) if established else None,
        status_notifies=selection.notifies if established else (),
        response=ParsedIKEResponse(
            mode=IKEMode.IKEV2,
            status=IKEParseStatus.RESPONDED if established else IKEParseStatus.UNBOUND,
            dh_groups=selection.groups,
            encryption=selection.encryption,
            prf=selection.prf,
            integrity=selection.integrity,
            transforms_offered=len(_BASE_TRANSFORMS) + 1 + (additional is not None),
        ),
    )


class LocalProbeError(Exception):
    """A fault on this host. Never a statement about the responder."""


def _exchange(
    sock: socket.socket, wire: bytes, address: str, port: int, retries: int, pace: float
) -> bytes | None:
    """Send and wait, retrying silence. Returns None when nothing valid arrived.

    Silence is retried because a rate-limiting responder and a dead address look
    identical on one datagram; only the retry separates them. A reply from
    another address is skipped rather than returned.
    """
    try:
        for attempt in range(retries + 1):
            try:
                sock.sendto(wire, (address, port))
            except OSError as exc:
                raise LocalProbeError(f"send failed: {exc}") from exc
            try:
                data, peer = sock.recvfrom(4096)
            except TimeoutError:
                if attempt < retries:
                    time.sleep(pace * (attempt + 1))
                continue
            except OSError as exc:
                raise LocalProbeError(f"receive failed: {exc}") from exc
            if peer[0] == address:
                return data
        return None
    finally:
        sock.close()


def _resolve(host: str) -> tuple[int, str]:
    """Resolve once, preferring IPv4 but accepting IPv6, and return (family, address).

    Resolution is done here so the reply-source check compares against the same
    address the datagram was sent to, and so an IPv6-only responder is reachable
    rather than silently unprobeable.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise LocalProbeError(f"cannot resolve {host}: {exc}") from exc
    for family in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == family:
                return family, info[4][0]
    raise LocalProbeError(f"no usable address for {host}")


def probe(
    host: str,
    port: int,
    key_exchange: int,
    *,
    additional: int | None = None,
    timeout: float = 4.0,
    retries: int = 1,
    pace: float = 0.4,
    source_port: int = 0,
) -> NativeProbe | None:
    """Send one IKE_SA_INIT. Returns None when no public value exists for the method."""
    packet = build_sa_init(key_exchange, additional)
    if packet is None:
        return None
    wire = _NON_ESP_MARKER + packet if port == _PORT_NAT_T else packet
    family, address = _resolve(host)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        # Bind explicitly so the source port is recorded rather than assumed.
        # Port 0 asks the kernel for an ephemeral port, which avoids the
        # "address already in use" a VPN client bound to 500 would cause.
        sock.bind(("", source_port))
        sock.settimeout(timeout)
    except OSError as exc:
        sock.close()
        raise LocalProbeError(f"cannot bind source port {source_port}: {exc}") from exc

    received = _exchange(sock, wire, address, port, retries, pace)
    if received is None:
        return _unanswered(key_exchange, additional)
    data = received
    if port == _PORT_NAT_T and data[:4] == _NON_ESP_MARKER:
        data = data[4:]
    return _parse(data, key_exchange, additional, sent_spi=packet[:8])


def sweep(host: str, port: int = 500, *, timeout: float = 4.0) -> tuple[NativeProbe, ...]:
    """Probe every key exchange method, then RFC 9370 additions against one that worked.

    A method with no local public value is skipped rather than reported as a
    refusal, so an unsupported local algorithm never reads as a responder fact.
    """
    probes: list[NativeProbe] = []
    accepted: int | None = None
    for method in _KE_SWEEP:
        result = probe(host, port, method, timeout=timeout)
        if result is None:
            continue
        probes.append(result)
        if result.response.status is IKEParseStatus.RESPONDED and accepted is None:
            accepted = method
        # A refusal names the group to use, so follow it once rather than guess.
        notify = result.response.responder_notify or ""
        if accepted is None and notify.startswith("INVALID_KE_PAYLOAD:expects_group_"):
            suggested = int(notify.rsplit("_", 1)[1])
            if suggested not in _KE_SWEEP:
                retry = probe(host, port, suggested, timeout=timeout)
                if retry is not None:
                    probes.append(retry)
                    if retry.response.status is IKEParseStatus.RESPONDED:
                        accepted = suggested
    if accepted is not None:
        for method in _ADDKE_SWEEP:
            result = probe(host, port, accepted, additional=method, timeout=timeout)
            if result is not None:
                probes.append(result)
    return tuple(probes)
