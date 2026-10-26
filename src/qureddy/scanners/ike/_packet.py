# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""IKEv2 IKE_SA_INIT wire format: constants, key generation and packet construction.

Split from the prober so one module owns what goes on the wire and the other
owns what is read back. Original note follows.

Native IKEv2 IKE_SA_INIT prober, an alternative backend to ``ike-scan``.

Stock ``ike-scan`` 1.9.5 predates RFC 8247 (2017), so its IKEv2 proposal carries
transforms a current responder refuses. RFC 7296 permits a responder to stay
silent rather than answer an unauthenticated initiator, so the subprocess
backend reports ``no_response`` for both a dead address and a live gateway whose
proposal simply did not overlap. Those are different facts and the posture axes
cannot separate them.

This backend sends a conforming IKE_SA_INIT carrying the RFC 8247 mandatory set
and reads the responder's own selection off the wire, which recovers three
things the text backend reports as unknown:

* the responder is live, proven by a non-zero responder SPI;
* the accepted proposal, read from the echoed SA payload rather than inferred;
* RFC 9370 additional-key-exchange support, present only when the responder
  echoes a Transform Type 5 it was offered.

An ``INVALID_KE_PAYLOAD`` notify carries the group the responder will accept
(RFC 7296 section 3.10.1), so a refusal names its own remedy and the sweep
retries with that group instead of ending.
"""

from __future__ import annotations

import secrets
import struct
import subprocess

# RFC 7296 section 3.2 payload types and section 3.1 header constants.
_P_SA, _P_KE, _P_NONCE, _P_NOTIFY = 33, 34, 40, 41
_EXCHANGE_SA_INIT = 34
_FLAG_INITIATOR, _FLAG_RESPONSE = 0x08, 0x20
_VERSION_2_0 = 0x20
_HEADER_LEN = 28

# RFC 7296 section 3.3.2 transform types. Types 5 to 11 are ADDKE1 to ADDKE7
# from RFC 9370 section 3 and share the Transform Type 4 identifier registry.
_T_ENCR, _T_PRF, _T_INTEG, _T_KE = 1, 2, 3, 4
#: RFC 9370 section 3 assigns ADDKE1 through ADDKE7 the values 6 to 12. Type 5
#: is unassigned, so offering it proves nothing: a responder is correct to
#: ignore it, and reading that silence as absent RFC 9370 support would be a
#: false negative.
_T_ADDKE1 = 6
_T_ADDKE_RANGE = range(6, 13)

#: RFC 7296 section 3.10.1. The notify data of an INVALID_KE_PAYLOAD holds the
#: group the responder expects, in two octets.
_NOTIFY_INVALID_KE = 17
_NOTIFY_NO_PROPOSAL = 14

#: RFC 3948 section 2.2: four zero octets aligned with an ESP SPI, so a
#: responder on 4500 can tell IKE from ESP.
_NON_ESP_MARKER = b"\x00\x00\x00\x00"

#: IKE listens on 500, and RFC 3947 floats to 4500 once a NAT is detected. Only
#: the 4500 datagram carries the Non-ESP Marker.
_PORT_IKE, _PORT_NAT_T = 500, 4500
#: Re-exported so an adapter names the float port rather than repeating 4500.
PORT_NAT_T = _PORT_NAT_T
#: Minimum bytes before a field can be read: the generic payload header, and the
#: notify header that follows it.
_PAYLOAD_HEADER_LEN, _NOTIFY_HEADER_LEN = 4, 8
#: A transform substructure is eight octets before any attribute.
_TRANSFORM_LEN = 8
#: A transform carrying a key-length attribute is at least twelve octets.
_TRANSFORM_WITH_ATTR_LEN = 12
#: Proposal substructure header, before the first transform.
_PROPOSAL_HEADER_LEN = 12
#: An INVALID_KE_PAYLOAD carries the accepted group in two octets.
_NOTIFY_GROUP_LEN = 2

#: Offered in every proposal: the RFC 8247 section 2.1 to 2.3 mandatory set,
#: widest first so the responder's choice reveals its preference order.
_BASE_TRANSFORMS: tuple[tuple[int, int, int | None], ...] = (
    (_T_ENCR, 20, 256),  # ENCR_AES_GCM_16, SHOULD
    (_T_ENCR, 20, 128),
    (_T_ENCR, 12, 256),  # ENCR_AES_CBC, MUST
    (_T_ENCR, 12, 128),
    (_T_PRF, 5, None),  # PRF_HMAC_SHA2_256, MUST
    (_T_PRF, 7, None),  # PRF_HMAC_SHA2_512, SHOULD+
    (_T_INTEG, 12, None),  # AUTH_HMAC_SHA2_256_128, MUST
    (_T_INTEG, 14, None),  # AUTH_HMAC_SHA2_512_256, SHOULD
)

#: Key exchange methods probed one per message. 35 to 37 are ML-KEM from
#: draft-ietf-ipsecme-ikev2-mlkem; they appear in the proposal so a supporting
#: responder can select one, and a responder that ignores them is recorded as
#: offering no post-quantum method rather than as having failed.
_KE_SWEEP = (19, 20, 21, 31, 35, 36, 37)
#: Additional key exchange methods tried under ADDKE1 against an accepted base.
_ADDKE_SWEEP = (31, 36, 35, 37, 20)

_NAMES_ENCR = {12: "AES-CBC", 20: "AES-GCM-16", 28: "CHACHA20-POLY1305"}
_NAMES_PRF = {5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512"}
_NAMES_INTEG = {
    0: "NONE",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
}
_NAMES_KE = {
    14: "MODP-2048",
    19: "ECP-256",
    20: "ECP-384",
    21: "ECP-521",
    31: "X25519",
    32: "X448",
    35: "ML-KEM-512",
    36: "ML-KEM-768",
    37: "ML-KEM-1024",
}


#: Key exchange methods this backend can produce a public value for, mapped to
#: the pinned OpenSSL algorithm and the raw public-value length RFC 5903,
#: RFC 8031 and draft-ietf-ipsecme-ikev2-mlkem assign them. Generation goes
#: through the OpenSSL CLI the engine already pins and ships, so the backend
#: adds no Python dependency and inherits ML-KEM the moment OpenSSL has it.
_KE_ALGORITHMS: dict[int, tuple[str, str | None, int]] = {
    19: ("EC", "P-256", 64),  # uncompressed x||y
    20: ("EC", "P-384", 96),
    21: ("EC", "P-521", 132),
    31: ("X25519", None, 32),
    35: ("ML-KEM-512", None, 800),
    36: ("ML-KEM-768", None, 1184),
    37: ("ML-KEM-1024", None, 1568),
}


def _public_value(method: int, openssl: str = "openssl") -> bytes | None:
    """Return an ephemeral public value for a key exchange method.

    The DER SubjectPublicKeyInfo wrapper varies by algorithm, so the raw value
    is taken from the tail at the length the relevant specification fixes. That
    keeps the parser independent of the encoding OpenSSL chooses and of any
    future algorithm whose wrapper differs. For the NIST curves the leading
    0x04 uncompressed-point octet is dropped, because RFC 5903 carries x||y
    alone in the IKEv2 Key Exchange payload.
    """
    entry = _KE_ALGORITHMS.get(method)
    if entry is None:
        return None
    algorithm, curve, width = entry
    argv = [openssl, "genpkey", "-algorithm", algorithm, "-outform", "DER"]
    if curve:
        argv += ["-pkeyopt", f"ec_paramgen_curve:{curve}"]
    try:
        key = subprocess.run(  # noqa: S603 - argv list, shell=False
            argv, capture_output=True, check=False, timeout=15
        ).stdout
        if not key:
            return None
        pub = subprocess.run(  # noqa: S603 - argv list, shell=False
            [openssl, "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
            input=key,
            capture_output=True,
            check=False,
            timeout=15,
        ).stdout
    except OSError, subprocess.SubprocessError:
        return None
    if len(pub) < width:
        return None
    return pub[-width:]


def available_methods(openssl: str = "openssl") -> tuple[int, ...]:
    """Return the key exchange methods this host can actually probe.

    A method OpenSSL cannot generate is excluded rather than reported as a
    responder refusal, so a local capability gap never reads as a remote fact.
    """
    return tuple(m for m in _KE_ALGORITHMS if _public_value(m, openssl) is not None)


def _transform(last: bool, t_type: int, t_id: int, key_bits: int | None) -> bytes:
    """RFC 7296 section 3.3.2 Transform Substructure, with the section 3.3.5 TV attribute."""
    attrs = struct.pack("!HH", 0x800E, key_bits) if key_bits else b""
    return (
        struct.pack("!BBH", 0 if last else 3, 0, 8 + len(attrs))
        + struct.pack("!BBH", t_type, 0, t_id)
        + attrs
    )


def _payload(next_payload: int, body: bytes) -> bytes:
    """RFC 7296 section 3.2 Generic Payload Header."""
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def build_sa_init(key_exchange: int, additional: int | None = None) -> bytes | None:
    """Build one IKE_SA_INIT, or None when no public value can be produced."""
    public = _public_value(key_exchange)
    if public is None:
        return None
    items = [*_BASE_TRANSFORMS, (_T_KE, key_exchange, None)]
    if additional is not None:
        items.append((_T_ADDKE1, additional, None))
    transforms = b"".join(
        _transform(i == len(items) - 1, t_type, t_id, bits)
        for i, (t_type, t_id, bits) in enumerate(items)
    )
    # Proposal 1, protocol IKE, no SPI. RFC 7296 section 3.3.1.
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, len(items)) + transforms
    body = (
        _payload(_P_KE, proposal)
        + _payload(_P_NONCE, struct.pack("!HH", key_exchange, 0) + public)
        + _payload(0, secrets.token_bytes(32))
    )
    header = struct.pack(
        "!8s8sBBBBII",
        secrets.token_bytes(8),
        b"\x00" * 8,
        _P_SA,
        _VERSION_2_0,
        _EXCHANGE_SA_INIT,
        _FLAG_INITIATOR,
        0,
        _HEADER_LEN + len(body),
    )
    return header + body
