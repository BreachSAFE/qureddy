# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Read an SSH server's cleartext KEXINIT posture. No crypto, no external binary.

SSH transmits its offered algorithm name-lists (RFC 4253 SSH_MSG_KEXINIT) in
cleartext, before key exchange -- so posture is readable with a plain socket and
zero dependencies. Every byte from the server is untrusted: bounded reads,
explicit timeout, typed errors on malformed input.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from qureddy.core.errors import SSHProbeError
from qureddy.core.logging import get_logger

_log = get_logger(__name__)

_SSH_MSG_KEXINIT = 20
_CLIENT_BANNER = b"SSH-2.0-qureddy\r\n"
_MAX_BANNER = 8192
_MAX_PACKET = 65536
# Negotiation markers that appear in a KEXINIT kex list but aren't real KEX algs.
_PSEUDO_KEX = frozenset({"ext-info-s", "ext-info-c", "kex-strict-s-v00@openssh.com"})


@dataclass(frozen=True, slots=True)
class SSHOffer:
    """The server's offered SSH posture (capability, not a negotiated result)."""

    server_banner: str
    kex_algorithms: tuple[str, ...]
    host_key_algorithms: tuple[str, ...]
    ciphers: tuple[str, ...] = ()
    macs: tuple[str, ...] = ()


def read_kexinit_offer(host: str, port: int, *, timeout_seconds: int) -> SSHOffer:
    """Return the server's offered KEX + host-key algorithm lists.

    Reads what the server *offers* (capability), not what one connection
    negotiates (client-dependent). Raises SSHProbeError on connect failure,
    timeout, or malformed/oversized response.
    """
    # Debug logging mirrors the TLS probe's subprocess.start/complete events
    # (structlog, visible at -vv/-vvv on stderr) so an operator can see the
    # socket exchange — and, on a slow/black-holed multi-homed host, see that
    # the connect is progressing rather than a silently frozen terminal.
    _log.debug("ssh_probe.connect", host=host, port=port, timeout_seconds=timeout_seconds)
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            banner = _read_banner(sock)
            _log.debug("ssh_probe.banner", banner=banner)
            sock.sendall(_CLIENT_BANNER)
            payload = _read_packet_payload(sock)
            kex, host_keys, ciphers, macs = _parse_kexinit(payload)
    except (OSError, TimeoutError) as exc:
        _log.debug("ssh_probe.failed", host=host, port=port, error=str(exc))
        msg = f"ssh probe of {host}:{port} failed: {exc}"
        raise SSHProbeError(msg) from exc
    real_kex = tuple(a for a in kex if a not in _PSEUDO_KEX)
    _log.debug(
        "ssh_probe.kexinit",
        kex_count=len(real_kex),
        host_key_count=len(host_keys),
        kex_algorithms=real_kex,
        host_key_algorithms=tuple(host_keys),
    )
    return SSHOffer(
        server_banner=banner,
        kex_algorithms=real_kex,
        host_key_algorithms=tuple(host_keys),
        ciphers=tuple(ciphers),
        macs=tuple(macs),
    )


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            msg = "connection closed mid-packet"
            # Peer closed the connection (clean EOF): a connectivity failure, not an
            # ambiguous parse. Chain a ConnectionError so build_ssh_failure_result maps
            # it to TARGET_CONNECT_FAILED rather than PARSE_AMBIGUOUS (#244).
            raise SSHProbeError(msg) from ConnectionError(msg)
        buf += chunk
    return bytes(buf)


def _read_banner(sock: socket.socket) -> str:
    # One byte at a time so we never consume bytes belonging to the following
    # KEXINIT packet. RFC 4253: server may emit comment lines before SSH-.
    total = 0
    while True:
        line = bytearray()
        while not line.endswith(b"\n"):
            chunk = sock.recv(1)
            if not chunk:
                msg = "connection closed before banner"
                # Peer closed before the banner: connectivity failure -> connect-failed (#244).
                raise SSHProbeError(msg) from ConnectionError(msg)
            line += chunk
            total += 1
            if total > _MAX_BANNER:
                msg = "server banner exceeded bound"
                raise SSHProbeError(msg)
        text = line.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
        if text.startswith(b"SSH-"):
            return text.decode("ascii", errors="replace")


def _read_packet_payload(sock: socket.socket) -> bytes:
    (pkt_len,) = struct.unpack(">I", _recvn(sock, 4))
    if not 1 <= pkt_len <= _MAX_PACKET:
        msg = f"implausible SSH packet length: {pkt_len}"
        raise SSHProbeError(msg)
    body = _recvn(sock, pkt_len)
    pad_len = body[0]
    if pad_len >= pkt_len:
        msg = "invalid SSH padding length"
        raise SSHProbeError(msg)
    return body[1 : len(body) - pad_len]


def _read_namelist(payload: bytes, off: int) -> tuple[list[str], int]:
    if off + 4 > len(payload):
        msg = "truncated KEXINIT (length field)"
        raise SSHProbeError(msg)
    (n,) = struct.unpack(">I", payload[off : off + 4])
    off += 4
    if off + n > len(payload):
        msg = "truncated KEXINIT (name-list body)"
        raise SSHProbeError(msg)
    raw = payload[off : off + n].decode("ascii", errors="replace")
    return (raw.split(",") if raw else []), off + n


def _parse_kexinit(payload: bytes) -> tuple[list[str], list[str], list[str], list[str]]:
    if not payload or payload[0] != _SSH_MSG_KEXINIT:
        msg = "response is not an SSH_MSG_KEXINIT"
        raise SSHProbeError(msg)
    off = 1 + 16  # msg byte + 16-byte cookie
    # KEXINIT name-lists in RFC 4253 §7.1 order: kex, host-key, then encryption and
    # MAC lists for each direction. #243: ciphers/MACs were never read past host-key.
    kex, off = _read_namelist(payload, off)
    host_keys, off = _read_namelist(payload, off)
    enc_c2s, off = _read_namelist(payload, off)
    enc_s2c, off = _read_namelist(payload, off)
    mac_c2s, off = _read_namelist(payload, off)
    mac_s2c, off = _read_namelist(payload, off)
    # Servers almost always offer the same set both directions; an order-preserving
    # union captures the full offered capability without duplicates.
    ciphers = list(dict.fromkeys(enc_c2s + enc_s2c))
    macs = list(dict.fromkeys(mac_c2s + mac_s2c))
    return kex, host_keys, ciphers, macs
