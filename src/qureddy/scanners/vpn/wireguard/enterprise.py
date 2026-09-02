# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""WireGuard Enterprise (provisioned) assessment (spike).

The base probe cannot assess WireGuard: it is silent to non-peers, even with a
valid mac1 (proven -- see probe.py). With customer-provisioned access (a
wg-quick config carrying their peer credentials), we complete the Noise
handshake and read the one variable that matters: is the deployment
quantum-hedged (psk2 PSK / Rosenpass) or naked Curve25519?

WireGuard has no crypto agility (fixed Curve25519 / ChaCha20-Poly1305 /
BLAKE2s), so there is nothing to enumerate. The whole value is ``hndl_hedge``.

The handshake is completed by the veepin sidecar (Go, MIT), the same wrap
pattern as ike-scan. It needs a tun, so it runs under the collector's privilege
model. Proven locally: a provisioned client completed the handshake in 4ms and
the server's latest-handshakes showed a fresh timestamp.

SPIKE: Rosenpass and obfuscation-fork detection are stubs; the veepin path and
flags are pinned loosely. See BreachSAFE/qureddy#742.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

_HANDSHAKE_RE = re.compile(r"handshake completed in (\d+)\s*ms", re.IGNORECASE)


def _read_config(config_path: str) -> dict[str, str]:
    """Flatten a wg-quick config to a lowercase key -> value map (last wins)."""
    values: dict[str, str] = {}
    for line in Path(config_path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, _, val = line.partition("=")
        if val:
            values[key.strip().lower()] = val.strip()
    return values


def _run_veepin(config_path: str, timeout: float) -> tuple[str, int | None]:
    """Complete the handshake via the veepin sidecar. Returns (state, ms)."""
    binary = shutil.which("veepin") or "/tmp/veepin"
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [binary, "probe", "wireguard", "-config", config_path, "-log-level", "info"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    match = _HANDSHAKE_RE.search(proc.stdout + proc.stderr)
    if match:
        return "completed", int(match.group(1))
    return "rejected", None


def assess(config_path: str, timeout: float = 15.0) -> dict[str, Any]:
    """Provisioned WireGuard assessment. The customer authorizes access by
    supplying ``config_path`` (their wg-quick peer config)."""
    cfg = _read_config(config_path)
    psk_in_use = "presharedkey" in cfg  # psk2 hedge is declared in the config
    state, ms = _run_veepin(config_path, timeout)

    # Rosenpass runs a separate PQC daemon (own UDP port); detecting it is a
    # separate probe. Stubbed for the spike.
    rosenpass = False
    obfuscation = None  # None | "amneziawg" (different init wire shape)

    hedged = psk_in_use or rosenpass
    return {
        "protocol": "wireguard",
        "tier": "enterprise",
        "authenticated": True,
        "handshake": state,
        "handshake_ms": ms,
        "psk2_in_use": psk_in_use,
        "rosenpass": rosenpass,
        "obfuscation": obfuscation,
        "key_exchange": "Curve25519",
        "verdict": "quantum_hedged" if hedged else "quantum_vulnerable",
        "hndl_hedge": "psk2" if psk_in_use else "rosenpass" if rosenpass else "none",
    }


if __name__ == "__main__":
    import json
    import sys

    print(json.dumps(assess(sys.argv[1]), indent=2))
