# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Validated connection-profile data used by OpenSSL ``s_client``."""

from __future__ import annotations

from qureddy.core.vocabulary import StartTLSMode
from qureddy.scanners.tls._net import build_connect_target

__all__ = ["StartTLSMode", "build_s_client_args", "starttls_args"]


def starttls_args(mode: StartTLSMode | None) -> tuple[str, ...]:
    """Return the bounded OpenSSL argument contribution for one connection."""
    return ("-starttls", mode.value) if mode is not None else ()


def build_s_client_args(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    extra: tuple[str, ...] = (),
    starttls: StartTLSMode | None = None,
) -> list[str]:
    """Build one bounded ``s_client`` argv for every TLS probe family."""
    args = [openssl_path, "s_client", "-connect", build_connect_target(host, port), *extra]
    args.extend(starttls_args(starttls))
    if sni is not None and sni.strip():
        args.extend(["-servername", sni])
    return args
