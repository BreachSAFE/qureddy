# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Hermetic tests for the native IKEv2 prober.

Every test builds a response in memory, so the suite reaches no network and no
responder. The adversarial cases matter most here: the parser reads a
length-delimited structure that an unauthenticated peer controls end to end,
and a datagram arrives from whoever sends one.
"""

from __future__ import annotations

import struct

import pytest

from qureddy.scanners.ike._packet import (
    _EXCHANGE_SA_INIT,
    _HEADER_LEN,
    _NON_ESP_MARKER,
    _T_ADDKE1,
    _VERSION_2_0,
    build_sa_init,
)
from qureddy.scanners.ike.native import _parse
from qureddy.scanners.ike.types import IKEMode, IKEParseStatus

SENT_SPI = b"\x01\x02\x03\x04\x05\x06\x07\x08"
RESPONDER_SPI = b"\xaa" * 8
_FLAG_RESPONSE = 0x20
_FLAG_INITIATOR = 0x08


def header(
    *,
    initiator: bytes = SENT_SPI,
    responder: bytes = RESPONDER_SPI,
    next_payload: int = 33,
    version: int = _VERSION_2_0,
    exchange: int = _EXCHANGE_SA_INIT,
    flags: int = _FLAG_RESPONSE,
    message_id: int = 0,
    length: int = _HEADER_LEN,
) -> bytes:
    """Build an IKE header, RFC 7296 section 3.1."""
    return struct.pack(
        "!8s8sBBBBII",
        initiator,
        responder,
        next_payload,
        version,
        exchange,
        flags,
        message_id,
        length,
    )


def transform(last: bool, t_type: int, t_id: int, key_bits: int | None = None) -> bytes:
    """Build a transform substructure, RFC 7296 section 3.3.2."""
    attrs = struct.pack("!HH", 0x800E, key_bits) if key_bits else b""
    return (
        struct.pack("!BBH", 0 if last else 3, 0, 8 + len(attrs))
        + struct.pack("!BBH", t_type, 0, t_id)
        + attrs
    )


def sa_payload(transforms: bytes, count: int, next_payload: int = 0) -> bytes:
    """Wrap transforms in a proposal and an SA payload."""
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, count) + transforms
    return struct.pack("!BBH", next_payload, 0, 4 + len(proposal)) + proposal


def accepted_response(*, addke: int | None = None) -> bytes:
    """A responder that selected AES-CBC-128 / SHA2-256 / ECP-256."""
    items = [
        transform(False, 1, 12, 128),
        transform(False, 2, 5),
        transform(False, 3, 12),
        transform(addke is None, 4, 19),
    ]
    if addke is not None:
        items.append(transform(True, _T_ADDKE1, addke))
    body = sa_payload(b"".join(items), len(items))
    return header(length=_HEADER_LEN + len(body)) + body


def notify_response(kind: int, data: bytes = b"") -> bytes:
    """A responder that refused, RFC 7296 section 3.10."""
    body = struct.pack("!BBHBBH", 0, 0, 8 + len(data), 0, 0, kind) + data
    return header(next_payload=41, responder=b"\x00" * 8, length=_HEADER_LEN + len(body)) + body


# --- the packet this prober sends -------------------------------------------


class TestPacket:
    """The request must be self-consistent before any response means anything."""

    def test_declared_length_matches_the_datagram(self) -> None:
        packet = build_sa_init(19)
        assert packet is not None
        declared = struct.unpack("!I", packet[24:28])[0]
        assert declared == len(packet)

    def test_header_identifies_an_initiating_sa_init(self) -> None:
        packet = build_sa_init(19)
        assert packet is not None
        _, responder, _, version, exchange, flags, msg_id, _ = struct.unpack(
            "!8s8sBBBBII", packet[:_HEADER_LEN]
        )
        assert responder == b"\x00" * 8, "SA_INIT carries no responder SPI"
        assert version == _VERSION_2_0
        assert exchange == _EXCHANGE_SA_INIT
        assert flags & _FLAG_INITIATOR
        assert msg_id == 0

    def test_payload_chain_stays_inside_the_datagram(self) -> None:
        packet = build_sa_init(19)
        assert packet is not None
        offset = _HEADER_LEN
        nxt = packet[16]
        seen = 0
        while nxt:
            _, _, plen = struct.unpack("!BBH", packet[offset : offset + 4])
            assert plen >= 4
            assert offset + plen <= len(packet)
            nxt = packet[offset]
            offset += plen
            seen += 1
        assert seen == 3, "SA, KE and nonce"

    def test_an_unsupported_method_yields_no_packet(self) -> None:
        # Rather than a malformed one. A local capability gap must never be
        # sent as a probe and then read back as a responder fact.
        assert build_sa_init(999) is None

    def test_additional_key_exchange_uses_the_rfc9370_type(self) -> None:
        packet = build_sa_init(19, 36)
        assert packet is not None
        assert _T_ADDKE1 == 6, "RFC 9370 section 3 assigns ADDKE1 the value 6"
        assert bytes([_T_ADDKE1, 0, 0, 36]) in packet


# --- response binding --------------------------------------------------------


class TestBinding:
    """A datagram arrives from anyone; only a bound reply is this target's."""

    @pytest.mark.parametrize(
        ("name", "data"),
        [
            ("foreign initiator SPI", header(initiator=b"\xff" * 8)),
            ("IKEv1 version", header(version=0x10)),
            ("different exchange", header(exchange=35)),
            ("non-zero message id", header(message_id=7)),
            ("request echoed back", header(flags=_FLAG_INITIATOR)),
        ],
    )
    def test_unbound_reply_is_not_an_answer(self, name: str, data: bytes) -> None:
        result = _parse(data, 19, None, sent_spi=SENT_SPI)
        assert result.response.status is IKEParseStatus.NO_RESPONSE, name
        assert result.responder_spi is None

    def test_bound_reply_with_a_selection_is_accepted(self) -> None:
        result = _parse(accepted_response(), 19, None, sent_spi=SENT_SPI)
        assert result.response.status is IKEParseStatus.RESPONDED
        assert result.responder_spi == RESPONDER_SPI.hex()


# --- what the responder selected --------------------------------------------


class TestSelection:
    """The transforms reported must be the responder's, never the request's."""

    def test_selected_transforms_are_read_from_the_response(self) -> None:
        response = _parse(accepted_response(), 19, None, sent_spi=SENT_SPI).response
        assert response.mode is IKEMode.IKEV2
        assert response.encryption == ("AES-CBC-128",)
        assert response.prf == ("HMAC-SHA2-256",)
        assert response.integrity == ("HMAC-SHA2-256-128",)
        assert response.dh_groups == ((19, "ECP-256"),)

    def test_echoed_additional_key_exchange_is_recorded(self) -> None:
        result = _parse(accepted_response(addke=36), 19, 36, sent_spi=SENT_SPI)
        assert result.additional_accepted == 36

    def test_an_ignored_additional_offer_is_not_a_selection(self) -> None:
        # RFC 9370 section 3: a supporting responder must select one of the
        # offered algorithms for any ADDKE type present. Silence is absence.
        result = _parse(accepted_response(), 19, 36, sent_spi=SENT_SPI)
        assert result.additional_accepted is None

    def test_a_zero_responder_spi_is_not_an_established_sa(self) -> None:
        body = accepted_response()[_HEADER_LEN:]
        data = header(responder=b"\x00" * 8, length=_HEADER_LEN + len(body)) + body
        result = _parse(data, 19, None, sent_spi=SENT_SPI)
        assert result.response.status is IKEParseStatus.UNBOUND
        assert result.responder_spi is None

    def test_a_header_without_payloads_is_not_an_established_sa(self) -> None:
        result = _parse(header(), 19, None, sent_spi=SENT_SPI)
        assert result.response.status is IKEParseStatus.UNBOUND


# --- refusals ----------------------------------------------------------------


class TestNotify:
    """A refusal is an answer, and an INVALID_KE_PAYLOAD names its own remedy."""

    def test_invalid_ke_payload_reports_the_group_to_retry(self) -> None:
        data = notify_response(17, struct.pack("!H", 19))
        result = _parse(data, 14, None, sent_spi=SENT_SPI)
        assert result.response.status is IKEParseStatus.REJECTED
        assert result.response.responder_notify == "INVALID_KE_PAYLOAD:expects_group_19"

    def test_no_proposal_chosen_is_named(self) -> None:
        result = _parse(notify_response(14), 19, None, sent_spi=SENT_SPI)
        assert result.response.responder_notify == "NO_PROPOSAL_CHOSEN"

    def test_an_unknown_notify_type_is_preserved_not_dropped(self) -> None:
        result = _parse(notify_response(9999), 19, None, sent_spi=SENT_SPI)
        assert result.response.responder_notify == "NOTIFY_9999"

    def test_invalid_ke_payload_without_data_still_parses(self) -> None:
        result = _parse(notify_response(17), 19, None, sent_spi=SENT_SPI)
        assert result.response.responder_notify == "INVALID_KE_PAYLOAD"

    def test_a_refusal_never_reports_transforms(self) -> None:
        result = _parse(notify_response(14), 19, None, sent_spi=SENT_SPI)
        assert result.response.encryption == ()
        assert result.response.dh_groups == ()


# --- adversarial input -------------------------------------------------------


class TestMalformed:
    """Every field is attacker-controlled; none may hang, crash or be believed."""

    @pytest.mark.parametrize(
        ("name", "data"),
        [
            ("empty", b""),
            ("one byte", b"\x00"),
            ("header truncated by one", header()[:-1]),
            ("payload length zero", header() + struct.pack("!BBH", 0, 0, 0)),
            # next_payload is non-zero so the walk would continue, and the
            # declared length is zero so the cursor would never advance. Only
            # the minimum-length guard ends this; without it the parser spins.
            ("zero length with a next payload", header() + struct.pack("!BBH", 33, 0, 0)),
            ("one-byte length with a next payload", header() + struct.pack("!BBH", 33, 0, 1)),
            ("payload length below header", header() + struct.pack("!BBH", 0, 0, 1)),
            ("payload length past the end", header() + struct.pack("!BBH", 0, 0, 65535)),
            ("self-referential chain", header() + struct.pack("!BBH", 33, 0, 4) * 64),
            (
                "proposal claims 255 transforms",
                header()
                + struct.pack("!BBH", 0, 0, 12)
                + struct.pack("!BBHBBBB", 0, 0, 8, 1, 1, 0, 255),
            ),
            (
                "transform length zero",
                header()
                + sa_payload(struct.pack("!BBH", 0, 0, 0) + struct.pack("!BBH", 1, 0, 12), 2),
            ),
            ("notify shorter than its header", header(next_payload=41) + b"\x00\x00\x00\x04"),
        ],
    )
    def test_malformed_input_is_refused_rather_than_believed(self, name: str, data: bytes) -> None:
        result = _parse(data, 19, None, sent_spi=SENT_SPI)
        assert result.response.status is not IKEParseStatus.RESPONDED, name
        assert result.responder_spi is None, name

    def test_a_truncated_transform_stops_the_walk(self) -> None:
        # The proposal declares four transforms and supplies one, so the walk
        # must stop at the datagram edge rather than read past it.
        body = sa_payload(transform(True, 4, 19), 4)
        data = header(length=_HEADER_LEN + len(body)) + body
        result = _parse(data, 19, None, sent_spi=SENT_SPI)
        assert result.response.dh_groups == ((19, "ECP-256"),)

    def test_an_unknown_transform_id_keeps_its_number(self) -> None:
        # Dropping it would hide a responder choosing something unrecognised.
        body = sa_payload(transform(True, 4, 1234), 1)
        data = header(length=_HEADER_LEN + len(body)) + body
        result = _parse(data, 19, None, sent_spi=SENT_SPI)
        assert result.response.dh_groups == ((1234, "1234"),)


# --- NAT-T framing -----------------------------------------------------------


def test_non_esp_marker_is_four_zero_octets() -> None:
    """RFC 3948 section 2.2, aligned with the SPI field of an ESP packet."""
    assert _NON_ESP_MARKER == b"\x00\x00\x00\x00"
    assert len(_NON_ESP_MARKER) == 4
