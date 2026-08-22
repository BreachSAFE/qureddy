# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Probe-result classification, timeout handling, and evidence integrity.

Split out of tests/test_openssl_probe.py (issue #298) along the
``openssl_probe/`` package seam: this module covers ``probe`` (stderr
classification, `run_hybrid_probe`) and ``_results`` (`result_from_timeout`),
leaving capability/version detection in the companion module.
"""

from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

import qureddy.scanners.tls.openssl_probe._constants as constants_module
from qureddy.core.models import FailureCategory, ProbeResult
from qureddy.scanners.tls.openssl_probe import (
    _classify_failure,
    run_hybrid_probe,
)
from qureddy.scanners.tls.openssl_probe._results import result_from_timeout
from tests._fake_openssl import fake_openssl


class TestTimeoutClassification:
    """A timeout is unreachable only when the TCP connect never completed (#138)."""

    @staticmethod
    def _timeout_result(output: bytes) -> ProbeResult:
        exc = subprocess.TimeoutExpired(cmd=["openssl"], timeout=2, output=output, stderr=b"")
        return result_from_timeout(["openssl"], exc.stdout, exc.stderr, datetime.now(UTC), 2, 1)

    def test_timeout_before_connect_is_unreachable(self) -> None:
        result = self._timeout_result(b"")
        assert result.failure_category is FailureCategory.TARGET_CONNECT_FAILED

    def test_timeout_after_connect_stays_handshake(self) -> None:
        result = self._timeout_result(b"CONNECTED(00000003)\n")
        assert result.failure_category is FailureCategory.TLS_HANDSHAKE_FAILED


class TestStderrClassification:
    """Probe-level stderr classification per blocker 4.

    The probe module itself classifies nonzero exits into specific
    failure categories so retry policy and policy classification get
    the right signal. Collapsing to TLS_HANDSHAKE_FAILED later loses
    that fidelity.
    """

    def test_connect_refused_is_target_connect_failed(self) -> None:
        result = run_hybrid_probe(
            fake_openssl("openssl_connect_refused"),
            "192.0.2.1",
            443,
            None,
            timeout_seconds=5,
        )
        assert result.return_code != 0
        assert result.failure_category is FailureCategory.TARGET_CONNECT_FAILED

    def test_handshake_failure_is_tls_handshake_failed(self) -> None:
        result = run_hybrid_probe(
            fake_openssl("openssl_handshake_failure"),
            "104.154.89.105",
            1012,
            None,
            timeout_seconds=5,
        )
        assert result.return_code != 0
        assert result.failure_category is FailureCategory.TLS_HANDSHAKE_FAILED

    def test_classify_failure_dispatch(self) -> None:
        """Direct check that _classify_failure picks the most specific category."""
        assert _classify_failure("connect:errno=61") is FailureCategory.TARGET_CONNECT_FAILED
        assert (
            _classify_failure("getaddrinfo: nodename nor servname provided")
            is FailureCategory.TARGET_CONNECT_FAILED
        )
        assert (
            _classify_failure("ssl/tls alert handshake failure")
            is FailureCategory.TLS_HANDSHAKE_FAILED
        )
        assert (
            _classify_failure("tlsv1 alert unrecognized name")
            is FailureCategory.SNI_REQUIRED_OR_WRONG
        )
        assert (
            _classify_failure("Connection reset by peer")
            is FailureCategory.MIDDLEBOX_OR_MTU_FAILURE
        )
        # Unknown stderr shape falls back to TLS_HANDSHAKE_FAILED.
        assert _classify_failure("") is FailureCategory.TLS_HANDSHAKE_FAILED
        assert _classify_failure("some weird unknown error") is FailureCategory.TLS_HANDSHAKE_FAILED


# Parametrized coverage for every classifier pattern. Lifted from
# the pre-archive test suite; each row is a real OpenSSL
# stderr fragment seen in the wild. Adding a new pattern to
# `_STDERR_SIGNATURES` should mean adding a row here in the same PR.
@pytest.mark.parametrize(
    ("stderr_fragment", "expected_category"),
    [
        # DNS / resolver
        ("getaddrinfo: nodename nor servname provided", FailureCategory.TARGET_CONNECT_FAILED),
        ("name or service not known", FailureCategory.TARGET_CONNECT_FAILED),
        ("could not resolve", FailureCategory.TARGET_CONNECT_FAILED),
        ("Temporary failure in name resolution", FailureCategory.TARGET_CONNECT_FAILED),
        # TCP-layer connect failures
        ("connect:errno=61", FailureCategory.TARGET_CONNECT_FAILED),
        ("connection refused on port 443", FailureCategory.TARGET_CONNECT_FAILED),
        ("Connection timed out", FailureCategory.TARGET_CONNECT_FAILED),
        ("Operation timed out", FailureCategory.TARGET_CONNECT_FAILED),
        ("No route to host", FailureCategory.TARGET_CONNECT_FAILED),
        ("Network is unreachable", FailureCategory.TARGET_CONNECT_FAILED),
        ("Host is down", FailureCategory.TARGET_CONNECT_FAILED),
        # SNI failures
        ("alert handshake failure", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("alert unrecognized name", FailureCategory.SNI_REQUIRED_OR_WRONG),
        ("SSL alert number 112", FailureCategory.SNI_REQUIRED_OR_WRONG),
        ("tlsv1 unrecognized name", FailureCategory.SNI_REQUIRED_OR_WRONG),
        # TLS handshake-level alerts
        ("SSL alert number 40", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("alert protocol version", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("inappropriate fallback", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("no shared cipher", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("no shared groups", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("wrong version number", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("unsupported protocol", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("decode error", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("decrypt error", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("bad record mac", FailureCategory.TLS_HANDSHAKE_FAILED),
        # Middlebox / MTU patterns
        ("EPIPE", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("Broken pipe", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("Connection reset by peer", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("ssl_read returned 0", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("ssl_read_internal: bad something", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("unexpected EOF while reading", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("Message too long", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("Fragmentation needed", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("premature close", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ],
)
def test_classify_failure_recognizes_known_patterns(
    stderr_fragment: str, expected_category: FailureCategory
) -> None:
    """Every entry in `_STDERR_SIGNATURES` has at least one test row.

    Lifted from the pre-archive implementation before that staging tree
    was archived. Ensures regressions don't quietly drop a pattern.
    """
    assert _classify_failure(stderr_fragment) is expected_category


class TestTimeoutPreservesPartialOutput:
    """`subprocess.TimeoutExpired` carries any output produced before
    the kill. The probe must NOT discard it.

    Reviewer-flagged bug: the legacy timeout branch replaced
    stdout/stderr with sha256(b"") and a synthetic message, losing
    forensic data. This test asserts the new behavior preserves bytes.
    """

    def test_timeout_preserves_partial_stdout_hash(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=["openssl"],
            timeout=1,
            output=b"CONNECTED(00000003)\npartial-stdout-marker\n",
            stderr=b"",
        )
        with patch(
            "qureddy.scanners.tls.openssl_probe.executor.subprocess.run", side_effect=timeout
        ):
            result = run_hybrid_probe(
                fake_openssl("openssl_ok"),
                "192.0.2.99",
                443,
                None,
                timeout_seconds=1,
            )
        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result.failure_category is FailureCategory.TLS_HANDSHAKE_FAILED
        assert result.return_code == -1
        # Stdout came through; hash is NOT the empty-string hash.
        assert result.stdout_sha256 != empty_hash, (
            "timeout branch lost partial stdout — should preserve bytes received before the kill"
        )
        assert "partial-stdout-marker" in result.stdout_excerpt

    def test_timeout_preserves_partial_stderr_with_marker(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=["openssl"],
            timeout=1,
            output=b"partial-stdout-marker\n",
            stderr=b"CONNECTION ESTABLISHED\n",
        )
        with patch(
            "qureddy.scanners.tls.openssl_probe.executor.subprocess.run", side_effect=timeout
        ):
            result = run_hybrid_probe(
                fake_openssl("openssl_ok"),
                "192.0.2.99",
                443,
                None,
                timeout_seconds=1,
            )
        # stderr captured the connection lines AND the timeout marker
        # the probe added on the timeout branch.
        assert "CONNECTION ESTABLISHED" in result.stderr_excerpt
        assert "[qureddy] timeout after 1s" in result.stderr_excerpt


class TestEvidenceIntegrityExcerptMatchesHash:
    """Issue #202: an excerpt must be derived from the same byte stream its
    sibling sha256 attests.

    `openssl s_client -brief` writes its transcript to stderr and leaves
    stdout empty. The pre-fix probe derived `stdout_excerpt` from the
    COMBINED stdout+stderr stream while `stdout_sha256` hashed stdout alone,
    so an empty-stdout probe emitted the empty-string hash beside an excerpt
    showing the whole stderr transcript. An auditor recomputing the hash
    would conclude the evidence had been altered.
    """

    @staticmethod
    def _completed(stdout: str, stderr: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["openssl", "s_client"], returncode=0, stdout=stdout, stderr=stderr
        )

    def _assert_stream_integrity(self, excerpt: str, sha256_hex: str, full_stream: str) -> None:
        """A consumer given `excerpt` + `full_stream` can verify the hash."""
        limit = constants_module.EXCERPT_LIMIT
        # The excerpt is a faithful prefix of the exact stream the hash attests.
        assert full_stream.startswith(excerpt)
        assert excerpt == full_stream[:limit]
        assert sha256_hex == hashlib.sha256(full_stream.encode("utf-8", "replace")).hexdigest()

    def test_empty_stdout_excerpt_matches_empty_stdout_hash(self) -> None:
        transcript = (
            "CONNECTED(00000003)\n"
            "Protocol version: TLSv1.3\n"
            "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
            "Negotiated TLS1.3 group: X25519MLKEM768\n"
        )
        # Real `s_client -brief`: transcript on stderr, stdout empty.
        with patch(
            "qureddy.scanners.tls.openssl_probe.executor.subprocess.run",
            return_value=self._completed("", transcript),
        ):
            result = run_hybrid_probe(fake_openssl("openssl_ok"), "example.com", 443, "example.com")

        empty_hash = hashlib.sha256(b"").hexdigest()
        assert result.stdout_sha256 == empty_hash
        # The honest excerpt beside an empty-stdout hash must ALSO be empty;
        # the bug showed the stderr transcript here (integrity mismatch).
        assert result.stdout_excerpt == ""
        # Both streams honour the integrity contract end to end.
        self._assert_stream_integrity(result.stdout_excerpt, result.stdout_sha256, "")
        self._assert_stream_integrity(result.stderr_excerpt, result.stderr_sha256, transcript)

    def test_stdout_excerpt_never_bleeds_stderr_bytes(self) -> None:
        stdout = "STDOUT-ONLY-BYTES\n"
        stderr = "STDERR-ONLY-BYTES\n"
        with patch(
            "qureddy.scanners.tls.openssl_probe.executor.subprocess.run",
            return_value=self._completed(stdout, stderr),
        ):
            result = run_hybrid_probe(fake_openssl("openssl_ok"), "example.com", 443, "example.com")

        # stdout_excerpt is derived from stdout ONLY — not the combined stream.
        assert result.stdout_excerpt == stdout
        assert "STDERR-ONLY-BYTES" not in result.stdout_excerpt
        self._assert_stream_integrity(result.stdout_excerpt, result.stdout_sha256, stdout)
        self._assert_stream_integrity(result.stderr_excerpt, result.stderr_sha256, stderr)
