# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Certificate fetch + parse via OpenSSL subprocess only (rapid prototype).

NOT the tracked MVP 0.2 implementation. Read-only — no minting, no key
generation, no private key material ever touched.

Rejected approach: the `cryptography` library. Per coding-rules.md §13.1 a
new dependency must replace 50+ lines we'd otherwise write; single-purpose
`openssl x509` flags (-subject/-issuer/-dates/-serial/-pubkey) do this in
under 40 lines with zero new dependencies, and it's the exact pattern
testssl.sh uses in production across years of real-world OpenSSL version
drift (verified: `reference/testssl/testssl.sh` greps confirm this). Thin
wrapper over the binary QuReddy already depends on — nothing new to add.

Kept out of openssl_probe.py (already 436 lines, past the 400-line hard
ceiling, tracked in issue #82) rather than adding to an over-ceiling file.
Still respects coding-rules.md §7: list-form args, shell=False, timeout on
every call, both streams captured, check=False with manual returncode
inspection.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

DEFAULT_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class CertificateInfo:
    """Read-only summary of one observed certificate. Nothing here is minted."""

    subject: str
    issuer: str
    not_before: str
    not_after: str
    serial: str
    signature_algorithm: str
    public_key_summary: str
    is_self_signed: bool


def fetch_certificate_pem(
    openssl_path: str, host: str, port: int, sni: str | None, *, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
) -> str:
    """Fetch the leaf certificate as PEM text via `openssl s_client`. Analysis mode: does not fail on untrusted/expired/self-signed chains, matches testssl.sh's -verify 1 -showcerts pattern."""
    args = [openssl_path, "s_client", "-connect", f"{host}:{port}", "-showcerts"]
    if sni is not None:
        args.extend(["-servername", sni])
    completed = subprocess.run(  # noqa: S603 -- list-form, shell=False
        args,
        input="",
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
        shell=False,
    )
    pem_start = completed.stdout.find("-----BEGIN CERTIFICATE-----")
    pem_end = completed.stdout.find("-----END CERTIFICATE-----")
    if pem_start == -1 or pem_end == -1:
        return ""
    return completed.stdout[pem_start : pem_end + len("-----END CERTIFICATE-----")]


def _x509(openssl_path: str, pem: str, *args: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> str:
    """One `openssl x509 -noout <args>` call against in-memory PEM text."""
    completed = subprocess.run(  # noqa: S603 -- list-form, shell=False
        [openssl_path, "x509", "-noout", *args],
        input=pem,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
        shell=False,
    )
    return completed.stdout.strip()


def parse_certificate(openssl_path: str, pem: str) -> CertificateInfo:
    """Parse a PEM certificate using single-purpose `openssl x509` flags only — no `-text` full-dump parsing except the one field (signature algorithm) with no dedicated flag, same as testssl.sh."""
    subject = _x509(openssl_path, pem, "-subject").removeprefix("subject=").strip()
    issuer = _x509(openssl_path, pem, "-issuer").removeprefix("issuer=").strip()
    dates = _x509(openssl_path, pem, "-dates")
    not_before = next((line.removeprefix("notBefore=") for line in dates.splitlines() if line.startswith("notBefore=")), "")
    not_after = next((line.removeprefix("notAfter=") for line in dates.splitlines() if line.startswith("notAfter=")), "")
    serial = _x509(openssl_path, pem, "-serial").removeprefix("serial=").strip()
    pubkey_text = _x509(openssl_path, pem, "-text")
    sig_line = next((line for line in pubkey_text.splitlines() if "Signature Algorithm" in line), "")
    sig_alg = sig_line.split(":", 1)[-1].strip() if sig_line else "UNKNOWN"
    pubkey_line = next((line for line in pubkey_text.splitlines() if "Public-Key:" in line), "")
    pubkey_summary = pubkey_line.strip() or "UNKNOWN"
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        signature_algorithm=sig_alg,
        public_key_summary=pubkey_summary,
        is_self_signed=subject == issuer,
    )
