# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for SSH posture classification and readiness rollup."""

from __future__ import annotations

import io
from unittest.mock import patch

from qureddy.core.errors import SSHProbeError
from qureddy.core.models import FailureCategory, Readiness
from qureddy.core.targets import parse_ssh_target
from qureddy.output.console import render_rich
from qureddy.scanners.ssh.probe import SSHOffer
from qureddy.scanners.ssh.scanner import build_ssh_failure_result, scan_ssh


def _run(kex: tuple[str, ...], host_keys: tuple[str, ...]):
    offer = SSHOffer(
        server_banner="SSH-2.0-test", kex_algorithms=kex, host_key_algorithms=host_keys
    )
    target = parse_ssh_target("test.invalid")
    with patch("qureddy.scanners.ssh.scanner.read_kexinit_offer", return_value=offer):
        return scan_ssh(target, timeout_seconds=1)


def test_pq_hybrid_offered_is_transitional_hybrid() -> None:
    r = _run(("mlkem768x25519-sha256", "curve25519-sha256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.TRANSITIONAL_HYBRID
    assert any(f.rule_id == "ssh.kex.hybrid_offered" for f in r.findings)


def test_classical_only_is_quantum_vulnerable() -> None:
    r = _run(("curve25519-sha256", "ecdh-sha2-nistp256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.QUANTUM_VULNERABLE
    assert any(f.rule_id == "ssh.kex.classical_only" for f in r.findings)


def test_weak_hostkey_rolls_up_to_classically_weak() -> None:
    # PQ hybrid offered BUT weak ssh-dss host key -> classically_weak wins
    r = _run(("mlkem768x25519-sha256",), ("ssh-dss", "ssh-ed25519"))
    assert r.summary.readiness is Readiness.CLASSICALLY_WEAK
    rules = {f.rule_id for f in r.findings}
    assert "ssh.kex.hybrid_offered" in rules
    assert "ssh.hostkey.weak" in rules


def test_scanner_name_and_scheme() -> None:
    r = _run(("mlkem768x25519-sha256",), ("ssh-ed25519",))
    assert r.scan.scanner_name == "ssh"
    assert r.target.scheme == "ssh"
    assert r.target.locator.startswith("ssh://")
    assert r.dependencies == ()  # SSH has no openssl dependency


def test_sntrup_also_counts_as_hybrid() -> None:
    r = _run(("sntrup761x25519-sha512@openssh.com", "curve25519-sha256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.TRANSITIONAL_HYBRID


def _failure_result(error: SSHProbeError):
    target = parse_ssh_target("test.invalid")
    return build_ssh_failure_result(target, error, cleaned_error="probe failed (cleaned)")


def test_failure_result_connect_cause_maps_to_target_connect_failed() -> None:
    """The probe raises connect failures `from` OSError/TimeoutError."""
    error = SSHProbeError("ssh probe of test.invalid:22 failed: connection refused")
    error.__cause__ = ConnectionRefusedError(61, "Connection refused")
    result = _failure_result(error)
    assert result.summary.failure_category is FailureCategory.TARGET_CONNECT_FAILED
    assert result.evidence[0].failure_category is FailureCategory.TARGET_CONNECT_FAILED


def test_failure_result_malformed_response_maps_to_parse_ambiguous() -> None:
    """Malformed-response failures are raised without a cause chain."""
    result = _failure_result(SSHProbeError("response is not an SSH_MSG_KEXINIT"))
    assert result.summary.failure_category is FailureCategory.PARSE_AMBIGUOUS


def test_failure_result_shape_matches_ssh_scan_contract() -> None:
    """Failure document mirrors the success shape: ssh scanner, no findings."""
    error = SSHProbeError("ssh probe of test.invalid:22 failed: timed out")
    error.__cause__ = TimeoutError()
    result = _failure_result(error)
    assert result.scan.scanner_name == "ssh"
    assert result.scan.status == "target_connect_failed"
    assert result.dependencies == ()  # SSH has no openssl dependency
    assert result.findings == ()
    assert result.summary.readiness is Readiness.UNKNOWN
    assert result.summary.finding_count == 0
    assert result.evidence[0].notes == ("probe failed (cleaned)",)


def test_ssh_rich_output_has_no_tls_cert_recommendation() -> None:
    """SSH scan must not emit the TLS cert-axis recommendation or probe rows."""
    r = _run(("mlkem768x25519-sha256",), ("ssh-ed25519",))
    buf = io.StringIO()
    render_rich(r, buf, verbosity=0)
    out = buf.getvalue()
    assert "certificate signature not yet inspected" not in out
    assert "cipher_suite" not in out
    assert "key_exchange" in out
    assert "host_keys" in out
