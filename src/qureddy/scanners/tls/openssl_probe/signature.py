# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bounded TLS signature-algorithm capability probes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.scanners.tls.connection import StartTLSMode, build_s_client_args
from qureddy.scanners.tls.openssl_probe._constants import DEFAULT_TIMEOUT_SECONDS
from qureddy.scanners.tls.openssl_probe.probe import _run_probe

if TYPE_CHECKING:
    from qureddy.core.models import ProbeResult

# OpenSSL 3.5 TLS names.  Keep this list explicit until the typed crypto registry
# owns the canonical aliases; legacy OpenSSL uses a different spelling.
MODERN_SIGNATURE_ALGORITHMS: tuple[str, ...] = (
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "ed25519",
    "ed448",
    "ecdsa_sha224",
    "ecdsa_sha1",
    "ecdsa_brainpoolP256r1tls13_sha256",
    "ecdsa_brainpoolP384r1tls13_sha384",
    "ecdsa_brainpoolP512r1tls13_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pss_pss_sha256",
    "rsa_pss_pss_sha384",
    "rsa_pss_pss_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "rsa_pkcs1_sha224",
    "rsa_pkcs1_sha1",
    "dsa_sha256",
    "dsa_sha384",
    "dsa_sha512",
    "dsa_sha224",
    "dsa_sha1",
    "mldsa44",
    "mldsa65",
    "mldsa87",
)

# OpenSSL 1.0.2u accepts the legacy RSA+HASH spelling and cannot advertise the
# modern TLS scheme registry through `openssl list`.
LEGACY_SIGNATURE_ALGORITHMS: tuple[str, ...] = (
    "RSA+SHA1",
    "RSA+SHA224",
    "RSA+SHA256",
    "RSA+SHA384",
    "RSA+SHA512",
)


def signature_algorithm_plan(runtime: str) -> tuple[str, ...]:
    """Return the runtime-specific TLS signature probe names."""
    return (
        LEGACY_SIGNATURE_ALGORITHMS if runtime == "openssl-legacy" else MODERN_SIGNATURE_ALGORITHMS
    )


def _requires_tls13(signature_algorithm: str) -> bool:
    """Return whether OpenSSL requires TLS 1.3 for this scheme name."""
    return signature_algorithm.startswith(("mldsa", "ecdsa_brainpool"))


def run_signature_algorithm_probe(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    signature_algorithm: str,
    runtime: str = "openssl",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    attempt_number: int = 1,
    starttls: StartTLSMode | None = None,
) -> ProbeResult:
    """Test whether a server accepts one client-advertised signature scheme."""
    tls_version = "-tls1_3" if _requires_tls13(signature_algorithm) else "-tls1_2"
    extra = [tls_version]
    if tls_version == "-tls1_2":
        cipher = "ALL" if runtime == "openssl-legacy" else "DEFAULT:@SECLEVEL=0"
        extra.extend(("-cipher", cipher))
    extra.extend(("-sigalgs", signature_algorithm, "-brief"))
    args = build_s_client_args(
        openssl_path,
        host,
        port,
        sni,
        extra=tuple(extra),
        starttls=starttls,
    )
    return _run_probe(args, timeout_seconds=timeout_seconds, attempt_number=attempt_number)
