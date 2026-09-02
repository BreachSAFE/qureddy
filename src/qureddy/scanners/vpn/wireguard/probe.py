# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""WireGuard probe (spike).

WireGuard has one fixed cipher set (Curve25519 + ChaCha20-Poly1305 + BLAKE2s)
and no negotiation, so there is nothing to enumerate. It is also silent by
design: it answers nothing without a provisioned peer keypair. This was proven
against a real endpoint -- an invalid-mac1 init AND a valid-mac1 init (computed
with the responder's public key) both got no response, because the Noise
handshake fails for a non-peer.

Therefore the probe is a best-effort presence hint plus a fixed verdict.
``SILENT`` is inconclusive (WireGuard OR a filtered/closed port), never "not
WireGuard". The crypto verdict is fixed: Curve25519 key establishment is
classical and quantum-vulnerable; base WireGuard has no PQC (Rosenpass is a
separate overlay). See BreachSAFE/qureddy#737.
"""

from __future__ import annotations

import os
import socket
from typing import Any

# WireGuard's fixed crypto (RFC/whitepaper), not negotiated.
_WIREGUARD_CRYPTO = {
    "key_exchange": "Curve25519",
    "aead": "ChaCha20-Poly1305",
    "hash": "BLAKE2s",
    "quantum_axis": "classical",
    "verdict": "quantum_vulnerable",
    "note": "no PQC in base WireGuard; Rosenpass adds a PQC overlay",
}

# Handshake-initiation shape: message type 1, three reserved zero bytes, then a
# fixed 148-byte body. First four bytes are 0x01 0x00 0x00 0x00.
_INIT_LEN = 148


def probe(host: str, port: int = 51820, timeout: float = 3.0) -> dict[str, Any]:
    """Best-effort presence hint plus the fixed WireGuard crypto verdict.

    ``probe == "silent"`` cannot confirm WireGuard (it is indistinguishable from
    a filtered port), so the verdict is only meaningful once the endpoint is
    known to be WireGuard from inventory.
    """
    packet = b"\x01\x00\x00\x00" + os.urandom(_INIT_LEN - 4)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (host, port))
        sock.recvfrom(2048)
        state = "responded"  # effectively never for a real WireGuard responder
    except socket.timeout:
        state = "silent"  # WireGuard OR filtered/closed -- inconclusive
    finally:
        sock.close()
    return {"protocol": "wireguard", "probe": state, "verdict": _WIREGUARD_CRYPTO}


if __name__ == "__main__":
    import json
    import sys

    print(json.dumps(probe(sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1")))
