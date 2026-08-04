# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for qureddy.scanners.tls.cert_probe (rapid-prototype module).

Written test-first against the python-oss-crypto-reviewer REJECT verdict
on the prowler-rapid-prototype branch: cert_probe.py had zero exception
handling for subprocess.TimeoutExpired / FileNotFoundError. These tests
must fail before the fix lands and pass after.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from qureddy.core.errors import LocalOpenSSLMissing
from qureddy.scanners.tls._net import build_connect_target
from qureddy.scanners.tls.cert_probe import (
    fetch_certificate_pem,
    parse_certificate,
)

FIXTURE_PEM = (Path(__file__).parent / "fixtures" / "certs" / "self_signed.pem").read_text()


def _x509_fixture(
    _openssl_path: str,
    _pem: str,
    flag: str,
    *,
    timeout_seconds: int,
) -> str:
    """Return deterministic OpenSSL x509 output without invoking a binary."""
    del timeout_seconds
    outputs = {
        "-subject": "subject=CN = test.example.invalid",
        "-issuer": "issuer=CN = test.example.invalid",
        "-dates": "notBefore=Jul 1 00:00:00 2026 GMT\nnotAfter=Jul 1 00:00:00 2027 GMT",
        "-serial": "serial=0123456789ABCDEF",
        "-text": (
            "    Signature Algorithm: sha256WithRSAEncryption\n"
            "                Public-Key: (2048 bit)"
        ),
    }
    return outputs[flag]


class TestFetchCertificatePem:
    """Subprocess failure paths — the two gaps the reviewer flagged."""

    def test_missing_binary_raises_local_openssl_missing(self) -> None:
        """FileNotFoundError from subprocess.run must become the same typed
        exception openssl_probe.py raises for a missing binary — not an
        unhandled traceback."""
        with (
            patch("subprocess.run", side_effect=FileNotFoundError("no such file")),
            pytest.raises(LocalOpenSSLMissing),
        ):
            fetch_certificate_pem("/nonexistent/openssl", "example.invalid", 443, None)

    def test_timeout_returns_empty_string_not_traceback(self) -> None:
        """A hung connection must degrade to 'no certificate observed'
        (empty string, same as the not-found case already handled), not
        crash the whole scan with an unhandled TimeoutExpired."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["openssl"], timeout=30),
        ):
            result = fetch_certificate_pem("/usr/bin/openssl", "example.invalid", 443, None)
        assert result == ""


class TestParseCertificate:
    """Parsing logic against a real, offline, deterministic fixture."""

    def test_self_signed_detected(self) -> None:
        with (
            patch("qureddy.scanners.tls.cert_probe._x509", side_effect=_x509_fixture),
            patch("qureddy.scanners.tls.cert_probe._is_self_signed", return_value=True),
        ):
            info = parse_certificate("/fixture/openssl", FIXTURE_PEM)
        assert info.is_self_signed is True
        assert "test.example.invalid" in info.subject
        assert info.subject == info.issuer

    def test_fields_are_populated_not_unknown_placeholders(self) -> None:
        with (
            patch("qureddy.scanners.tls.cert_probe._x509", side_effect=_x509_fixture),
            patch("qureddy.scanners.tls.cert_probe._is_self_signed", return_value=True),
        ):
            info = parse_certificate("/fixture/openssl", FIXTURE_PEM)
        assert info.serial
        assert info.signature_algorithm != "UNKNOWN"
        assert info.public_key_summary != "UNKNOWN"

    def test_empty_pem_raises_instead_of_silently_claiming_self_signed(self) -> None:
        """Reviewer-flagged bug: subject='' == issuer='' on a failed fetch
        made every failed fetch look like a self-signed cert. Must fail
        loud, not compute a silently-wrong answer (trap #11 shape)."""
        with pytest.raises(ValueError, match="empty"):
            parse_certificate("/fixture/openssl", "")


class TestBuildConnectTarget:
    """IPv6 bracketing (trap #13) and empty-SNI (trap #17) — both named
    explicitly in this project's own review-skill trap list, neither
    applied to this module until this test."""

    def test_ipv4_host_unbracketed(self) -> None:
        assert build_connect_target("192.0.2.1", 443) == "192.0.2.1:443"

    def test_hostname_unbracketed(self) -> None:
        assert build_connect_target("example.invalid", 443) == "example.invalid:443"

    def test_ipv6_host_bracketed(self) -> None:
        assert build_connect_target("::1", 443) == "[::1]:443"
        assert build_connect_target("2001:db8::1", 443) == "[2001:db8::1]:443"


class TestEmptySniGuard:
    def test_empty_sni_not_passed_as_servername(self) -> None:
        """`-servername \"\"` is rejected by many servers (trap #17) — an
        empty or whitespace SNI must be treated the same as sni=None."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            fetch_certificate_pem("/usr/bin/openssl", "example.invalid", 443, "   ")
        args = mock_run.call_args[0][0]
        assert "-servername" not in args
