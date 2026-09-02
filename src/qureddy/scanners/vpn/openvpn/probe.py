# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Unauthenticated OpenVPN probe (spike).

Reaches the TLS ServerHello through OpenVPN's control channel
(HARD_RESET -> ClientHello -> read ServerHello) and reads the negotiated TLS
version and cipher. No client certificate is required: the ServerHello arrives
before client-auth. Because the ClientHello is hand-built (not OpenSSL), the
probe can offer and observe suites OpenSSL 3.5.7 compiled out (3DES, RC4, NULL,
EXPORT) -- the #706 blind spot, inside a VPN tunnel a raw TLS scanner cannot
reach.

Proven locally against ``openvpn --tls-server --dev null`` with
``tls-version-min 1.0`` + ``tls-cipher DEFAULT:@SECLEVEL=0``:
``{"protocol": "openvpn", "tls_version": "TLS1.0", "cipher": "0x0035",
"cipher_name": "AES256-CBC-SHA", "insecure": True}``.

SPIKE: control-channel fragmentation and tls-crypt/tls-auth handling are not yet
robust; the weak-suite table is inline pending the crypto registry (#708). See
BreachSAFE/qureddy#737.
"""

from __future__ import annotations

import os
import socket
import struct
from typing import Any

# TLS wire versions.
_VERSIONS = {
    0x0300: "SSLv3",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}

# Suites we treat as insecure if the server selects one. Inline for the spike;
# the crypto registry (#708) becomes the source of truth.
_WEAK_SUITES = {
    0x0005: "RC4",
    0x0009: "DES-CBC",
    0x000A: "3DES-CBC",
    0x002F: "AES128-CBC-SHA",
    0x0035: "AES256-CBC-SHA",
    0x0033: "DHE-AES128-CBC-SHA",
    0x0039: "DHE-AES256-CBC-SHA",
}

# Offer weak suites first, then a couple of strong ones so a hardened server
# still completes the ServerHello.
_OFFER = list(_WEAK_SUITES) + [0x009C, 0x1301]

# OpenVPN control opcodes (<< 3 in the first byte).
_P_CONTROL_HARD_RESET_CLIENT_V2 = 7
_P_CONTROL_HARD_RESET_SERVER_V2 = 8
_P_CONTROL_V1 = 4
_P_ACK_V1 = 5


def _control(opcode: int, sid: bytes, acks: list[int], remote_sid: bytes,
             packet_id: int, payload: bytes = b"") -> bytes:
    """Frame an OpenVPN control packet: opcode<<3, session id, ACK array,
    remote session id (only when acking), packet id, then the payload."""
    out = bytes([(opcode << 3) | 0]) + sid + bytes([len(acks)])
    for acked in acks:
        out += struct.pack(">I", acked)
    if acks:
        out += remote_sid
    return out + struct.pack(">I", packet_id) + payload


def _parse(datagram: bytes) -> tuple[int, bytes, list[int], bytes, int, bytes]:
    opcode = datagram[0] >> 3
    off = 1
    sid = datagram[off:off + 8]
    off += 8
    ack_count = datagram[off]
    off += 1
    acks = [
        struct.unpack(">I", datagram[off + 4 * i:off + 4 * i + 4])[0]
        for i in range(ack_count)
    ]
    off += 4 * ack_count
    remote_sid = datagram[off:off + 8] if ack_count else b""
    off += 8 if ack_count else 0
    packet_id = struct.unpack(">I", datagram[off:off + 4])[0]
    off += 4
    return opcode, sid, acks, remote_sid, packet_id, datagram[off:]


def _client_hello() -> bytes:
    """A minimal TLS 1.0 ClientHello offering the suites in ``_OFFER``. Built by
    hand so no crypto library is needed to name a compiled-out cipher."""
    suites = b"".join(struct.pack(">H", c) for c in _OFFER)
    body = (
        b"\x03\x01"                      # client_version TLS 1.0
        + os.urandom(32)                 # random
        + b"\x00"                        # session id length
        + struct.pack(">H", len(suites)) + suites
        + b"\x01\x00"                    # 1 compression method: null
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def probe(host: str, port: int = 1194, timeout: float = 4.0) -> dict[str, Any]:
    """Return the negotiated OpenVPN control-channel TLS crypto, or a coverage
    state. ``{"protocol": None}`` means no OpenVPN reset response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sid = os.urandom(8)

    sock.sendto(_control(_P_CONTROL_HARD_RESET_CLIENT_V2, sid, [], b"", 0), (host, port))
    try:
        opcode, server_sid, _, _, server_pid, _ = _parse(sock.recvfrom(2048)[0])
    except socket.timeout:
        sock.close()
        return {"protocol": None, "coverage": "no_response"}
    if opcode != _P_CONTROL_HARD_RESET_SERVER_V2:
        sock.close()
        return {"protocol": None}

    sock.sendto(
        _control(_P_CONTROL_V1, sid, [server_pid], server_sid, 1, _client_hello()),
        (host, port),
    )
    tls = b""
    try:
        for _ in range(8):
            opcode, _s, _a, _r, packet_id, payload = _parse(sock.recvfrom(4096)[0])
            if opcode == _P_CONTROL_V1:
                tls += payload
                sock.sendto(_control(_P_ACK_V1, sid, [packet_id], server_sid, 0), (host, port))
    except socket.timeout:
        pass
    sock.close()

    start = tls.find(b"\x16\x03")
    if start < 0 or tls[start + 5:start + 6] != b"\x02":
        return {"protocol": "openvpn", "coverage": "not_testable", "tls": None}
    handshake = tls[start + 5:]
    version = struct.unpack(">H", handshake[4:6])[0]
    off = 6 + 32
    off += 1 + handshake[off]  # skip session id
    cipher = struct.unpack(">H", handshake[off:off + 2])[0]
    return {
        "protocol": "openvpn",
        "tls_version": _VERSIONS.get(version, hex(version)),
        "cipher": f"0x{cipher:04X}",
        "cipher_name": _WEAK_SUITES.get(cipher, "?"),
        "insecure": version <= 0x0302 or cipher in _WEAK_SUITES,
    }


if __name__ == "__main__":
    import json
    import sys

    print(json.dumps(probe(sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1")))
