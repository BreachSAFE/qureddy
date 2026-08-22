# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Real-crypto self-signed verification path in cert_probe (issue #109, #224).

Covers cert_probe.py:194-215 -- the `_is_self_signed` cryptographic check that
writes the cert to a temp file, runs `openssl verify -check_ss_sig -CAfile`, and
resolves nonzero exit to `False`, timeout to `None`, and launch errors as typed
exceptions. These tests
drive the real function through the public `parse_certificate` entrypoint and
assert the observable `is_self_signed` verdict, never that a private returned.

Hermetic: `subprocess.run` is injected; no OpenSSL binary and no network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from qureddy.core.errors import LocalOpenSSLBroken, LocalOpenSSLMissing
from qureddy.scanners.tls.cert_probe import parse_certificate

FIXTURE_PEM = (Path(__file__).parent / "fixtures" / "certs" / "self_signed.pem").read_text()

# Same shape as tests/test_cert_probe.py so subject == issuer (the cheap
# self-issued precondition passes and the real verify path is exercised).
_SELF_ISSUED_X509 = {
    "-subject": "subject=CN = test.example.invalid",
    "-issuer": "issuer=CN = test.example.invalid",
    "-dates": "notBefore=Jul 1 00:00:00 2026 GMT\nnotAfter=Jul 1 00:00:00 2027 GMT",
    "-serial": "serial=0123456789ABCDEF",
    "-text": "    Signature Algorithm: sha256WithRSAEncryption\n                Public-Key: (2048 bit)",
}


def _x509_self_issued(_openssl_path: str, _pem: str, flag: str, *, timeout_seconds: int) -> str:
    """Deterministic x509 field output with matching subject/issuer DNs."""
    del timeout_seconds
    return _SELF_ISSUED_X509[flag]


def _completed(returncode: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["openssl", "verify"], returncode=returncode, stdout="", stderr=""
    )


class TestIsSelfSignedVerifyPath:
    """cert_probe.py:194-215 -- the temp-file + `openssl verify` crypto check."""

    def test_verify_exit_zero_confirms_self_signed(self) -> None:
        """A passing `openssl verify -check_ss_sig` (exit 0) is the only thing
        that lets is_self_signed be True -- DN equality alone never proves it."""
        with (
            patch("qureddy.scanners.tls.cert_probe._x509", side_effect=_x509_self_issued),
            patch(
                "qureddy.scanners.tls.openssl_probe.executor.subprocess.run",
                return_value=_completed(0),
            ),
        ):
            info = parse_certificate("/fixture/openssl", FIXTURE_PEM)
        assert info.is_self_signed is True
        assert info.subject == info.issuer

    def test_verify_nonzero_exit_is_not_self_signed(self) -> None:
        """subject==issuer but the signature check fails (exit 2, "certificate
        signature failure"): self-issued-but-not-self-signed must read False."""
        with (
            patch("qureddy.scanners.tls.cert_probe._x509", side_effect=_x509_self_issued),
            patch(
                "qureddy.scanners.tls.openssl_probe.executor.subprocess.run",
                return_value=_completed(2),
            ),
        ):
            info = parse_certificate("/fixture/openssl", FIXTURE_PEM)
        assert info.is_self_signed is False

    def test_verify_timeout_resolves_to_unknown(self) -> None:
        """A hung `openssl verify` leaves self-signature verification unknown."""
        with (
            patch("qureddy.scanners.tls.cert_probe._x509", side_effect=_x509_self_issued),
            patch(
                "qureddy.scanners.tls.openssl_probe.executor.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["openssl", "verify"], timeout=30),
            ),
        ):
            info = parse_certificate("/fixture/openssl", FIXTURE_PEM)
        assert info.is_self_signed is None

    def test_verify_oserror_propagates_typed_local_error(self) -> None:
        """#374 security fix: an OSError launching `openssl verify` (a
        non-executable path / Windows WinError 193) is a broken *local*
        toolchain, so it must propagate as the typed exit-3 error — NOT be
        swallowed as `is_self_signed=False`, which would silently make every
        cert look not-self-signed whenever the local openssl is broken."""
        with (
            patch("qureddy.scanners.tls.cert_probe._x509", side_effect=_x509_self_issued),
            patch(
                "qureddy.scanners.tls.openssl_probe.executor.subprocess.run",
                side_effect=OSError("exec format error"),
            ),
            pytest.raises(LocalOpenSSLBroken),
        ):
            parse_certificate("/fixture/openssl", FIXTURE_PEM)

    def test_verify_missing_binary_propagates_typed_local_error(self) -> None:
        """A missing openssl in the verify path is a local-dependency failure,
        so it must propagate as LocalOpenSSLMissing (exit-3), never resolve to
        a silent is_self_signed=False (#374)."""
        with (
            patch("qureddy.scanners.tls.cert_probe._x509", side_effect=_x509_self_issued),
            patch(
                "qureddy.scanners.tls.openssl_probe.executor.subprocess.run",
                side_effect=FileNotFoundError("no such file"),
            ),
            pytest.raises(LocalOpenSSLMissing),
        ):
            parse_certificate("/fixture/openssl", FIXTURE_PEM)

    def test_temp_cert_file_is_removed_after_verify(self) -> None:
        """The securely-created temp cert file must be unlinked in `finally`
        regardless of the verify outcome (cert_probe.py:211-214)."""
        captured: dict[str, str] = {}

        def _capture(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            # `openssl verify -check_ss_sig -CAfile <path> <path>` -- the cert
            # path is the last argument and is written as a real temp file.
            captured["cert_path"] = args[-1]
            return _completed(0)

        with (
            patch("qureddy.scanners.tls.cert_probe._x509", side_effect=_x509_self_issued),
            patch(
                "qureddy.scanners.tls.openssl_probe.executor.subprocess.run", side_effect=_capture
            ),
        ):
            parse_certificate("/fixture/openssl", FIXTURE_PEM)

        assert captured["cert_path"], "verify should have been invoked with a temp cert file"
        assert not Path(captured["cert_path"]).exists(), "temp cert file must be cleaned up"
