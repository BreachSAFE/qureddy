# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Live network tests against the canonical MVP 0.1 targets.

Per docs/contributors/coding-rules.md Rule 9.4 these run as part of the default
suite. pytest-rerunfailures absorbs transient internet hiccups
(3 retries, 1s delay; configured globally in pyproject.toml).
"""

from __future__ import annotations

import os
import shutil

import pytest

from qureddy.core.errors import LocalOpenSSLMissing
from qureddy.core.models import FailureCategory, Readiness
from qureddy.core.targets import parse_target
from qureddy.scanners.tls.openssl_probe import probe_capability, resolve_openssl_path
from qureddy.scanners.tls.scanner import TLSScanner


def _openssl_path() -> str:
    """Resolve a real OpenSSL 3.5+ binary that supports X25519MLKEM768.

    Order: explicit homebrew openssl@3.5 → `QUREDDY_OPENSSL` → `PATH`.
    Live tests skip cleanly if no capable binary is present so a
    contributor on a stock distro is not forced to install OpenSSL 3.5
    just to run the suite.
    """
    candidates = [
        "/opt/homebrew/opt/openssl@3.5/bin/openssl",
        os.environ.get("QUREDDY_OPENSSL"),
        shutil.which("openssl"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            try:
                resolved = resolve_openssl_path(candidate)
            except LocalOpenSSLMissing:
                continue
            try:
                dep = probe_capability(resolved)
            except (LocalOpenSSLMissing, OSError):
                continue
            if dep.failure_category is None and dep.supports_x25519mlkem768:
                return resolved
    pytest.skip(
        "no OpenSSL 3.5+ binary with X25519MLKEM768 found "
        "(install openssl@3.5 or set QUREDDY_OPENSSL)",
    )
    raise RuntimeError("unreachable")


@pytest.fixture
def scanner() -> TLSScanner:
    return TLSScanner(openssl_path=_openssl_path())


def test_pq_cloudflareresearch_hybrid(scanner: TLSScanner) -> None:
    """UC1: pq.cloudflareresearch.com must report transitional_hybrid."""
    target = parse_target("pq.cloudflareresearch.com")
    result = scanner.scan(target)
    assert result.summary.readiness is Readiness.TRANSITIONAL_HYBRID
    assert any(f.rule_id == "tls.hybrid.negotiated_x25519mlkem768" for f in result.findings)


def test_example_com_classical_control_fires(scanner: TLSScanner) -> None:
    """UC2: example.com's classical control probe must produce a
    quantum_vulnerable finding.

    Note: as of 2026-04, Cloudflare-fronted endpoints (including
    example.com) negotiate hybrid by default when offered, so the
    HYBRID probe also succeeds. The use case requires that the
    classical X25519 result is reported as quantum_vulnerable, not
    that hybrid is absent. This assertion checks exactly that.
    """
    target = parse_target("example.com")
    result = scanner.scan(target)
    assert any(
        f.rule_id == "tls.classical.negotiated_x25519"
        and f.readiness is Readiness.QUANTUM_VULNERABLE
        for f in result.findings
    )


def test_one_one_one_one_with_sni(scanner: TLSScanner) -> None:
    """UC3: scanning 1.1.1.1:443 with --sni one.one.one.one normalizes
    correctly and produces a valid result without a usage error."""
    target = parse_target("1.1.1.1:443", sni_override="one.one.one.one")
    assert target.host == "1.1.1.1"
    assert target.sni == "one.one.one.one"
    result = scanner.scan(target)
    assert result.summary.target == "tls://1.1.1.1:443"


def test_tls12_only_handshake_failure(scanner: TLSScanner) -> None:
    """UC5: tls-v1-2.badssl.com:1012 must fail with tls_handshake_failed.

    The endpoint forces TLS 1.2 only; the scanner requires TLS 1.3.
    The probe returns nonzero; the scanner reports the failure path
    rather than crashing.
    """
    target = parse_target("tls-v1-2.badssl.com:1012")
    result = scanner.scan(target)
    assert result.summary.failure_category is FailureCategory.TLS_HANDSHAKE_FAILED
    assert any(f.rule_id == "tls.hybrid.probe_failed" for f in result.findings)


def test_www_cloudflare_completes_within_timeout(scanner: TLSScanner) -> None:
    """www.cloudflare.com completes a scan within the default timeout."""
    target = parse_target("www.cloudflare.com")
    result = scanner.scan(target)
    assert result.summary.target == "tls://www.cloudflare.com:443"


def test_www_google_completes_within_timeout(scanner: TLSScanner) -> None:
    """www.google.com completes a scan within the default timeout."""
    target = parse_target("www.google.com")
    result = scanner.scan(target)
    assert result.summary.target == "tls://www.google.com:443"
