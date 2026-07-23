# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared `-connect host:port` construction for the TLS probe modules.

Extracted after the same fix (issue #187's bug class) landed twice
independently in `cert_probe.py` and `legacy_probe.py`, with a third
occurrence (`openssl_probe.py` itself, issue #187) already filed and
waiting — past this project's own "tolerate two copies, extract on the
third" threshold (docs/contributors/agent-antipatterns.md).
"""

from __future__ import annotations


def build_connect_target(host: str, port: int) -> str:
    """Build the `host:port` string for `-connect`, bracketing IPv6 literals.

    `ScanTarget` stores IPv6 hosts unbracketed (see core/targets.py
    `_parse_bracketed_ipv6`), so `192.0.2.1:443` needs no change but
    `::1` needs to become `[::1]:443` — an unbracketed IPv6 host:port is
    ambiguous (which colon is the port separator?). A bare colon count
    is a sufficient IPv6 heuristic here: no valid hostname or IPv4
    literal ever contains one.
    """
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"
