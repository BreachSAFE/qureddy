# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for SSH posture classification and readiness rollup."""

from __future__ import annotations

import io
import json
from unittest.mock import patch

from qureddy.core.models import Readiness
from qureddy.core.targets import parse_ssh_target
from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.scanners.ssh.probe import SSHOffer
from qureddy.scanners.ssh.scanner import scan_ssh


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


def test_ssh_hybrid_observation_emits_17_crypto_assets() -> None:
    result = _run(("mlkem768x25519-sha256", "curve25519-sha256"), ("ssh-ed25519",))
    stream = io.StringIO()

    render_cbom(result, stream)

    payload = json.loads(stream.getvalue())
    components = {item["bom-ref"]: item for item in payload["components"]}
    assert payload["specVersion"] == "1.7"
    assert "crypto/algorithm/mlkem768x25519-sha256" in components
    protocol = components["crypto/protocol/ssh-2.0"]["cryptoProperties"]["protocolProperties"]
    assert protocol == {"type": "ssh", "version": "2.0"}


def test_ssh_rsa_sha1_hostkey_flagged_weak() -> None:
    # A2/#143: ssh-rsa (SHA-1, RFC 8332) is weak even when no ssh-dss is offered.
    r = _run(("curve25519-sha256",), ("ssh-rsa", "rsa-sha2-256", "ssh-ed25519"))
    assert r.summary.readiness is Readiness.CLASSICALLY_WEAK
    weak = next(f for f in r.findings if f.rule_id == "ssh.hostkey.weak")
    assert "ssh-rsa" in weak.title
    # rsa-sha2-256 (SHA-2) and ssh-ed25519 must NOT be dragged into the weak set.
    assert "rsa-sha2-256" not in weak.title
    assert "ssh-ed25519" not in weak.title


def test_weak_kex_group1_sha1_flagged() -> None:
    # A2/#143: widen weak detection to the KEX name-list the probe already collects.
    r = _run(("diffie-hellman-group1-sha1", "curve25519-sha256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.CLASSICALLY_WEAK
    weak = next(f for f in r.findings if f.rule_id == "ssh.kex.weak")
    assert "diffie-hellman-group1-sha1" in weak.title


def test_strong_kex_and_hostkeys_have_no_weak_findings() -> None:
    # A modern offer must not raise a false weak KEX/host-key finding.
    r = _run(("curve25519-sha256", "diffie-hellman-group14-sha256"), ("ssh-ed25519",))
    rules = {f.rule_id for f in r.findings}
    assert "ssh.kex.weak" not in rules
    assert "ssh.hostkey.weak" not in rules


def test_host_keys_emitted_as_cbom_components() -> None:
    # A5/#143: the CBOM previously dropped host keys; every offered host key must
    # now appear as a signature-classified crypto asset the endpoint provides.
    result = _run(("curve25519-sha256",), ("ssh-ed25519", "rsa-sha2-256"))
    stream = io.StringIO()
    render_cbom(result, stream)
    payload = json.loads(stream.getvalue())
    components = {item["bom-ref"]: item for item in payload["components"]}
    assert "crypto/algorithm/ssh-ed25519" in components
    assert "crypto/algorithm/rsa-sha2-256" in components
    # Classified honestly as classical signatures (no PQ resistance).
    props = components["crypto/algorithm/ssh-ed25519"]["cryptoProperties"]["algorithmProperties"]
    assert props["primitive"] == "signature"
    assert props["nistQuantumSecurityLevel"] == 0
    endpoint = next(d for d in payload["dependencies"] if d["ref"] == "endpoint")
    assert "crypto/algorithm/ssh-ed25519" in endpoint["provides"]
    assert "crypto/algorithm/rsa-sha2-256" in endpoint["provides"]


def test_weak_dss_hostkey_present_in_cbom_inventory() -> None:
    # A5/#143: the specific gap called out live — a weak ssh-dss host key was
    # observed yet absent from the CBOM. It must now be an inventory component.
    result = _run(("mlkem768x25519-sha256",), ("ssh-dss", "ssh-ed25519"))
    stream = io.StringIO()
    render_cbom(result, stream)
    payload = json.loads(stream.getvalue())
    refs = {item["bom-ref"] for item in payload["components"]}
    assert "crypto/algorithm/ssh-dss" in refs
    assert "crypto/algorithm/ssh-ed25519" in refs
    # The PQ hybrid KEX asset stays a KEM group, not a signature.
    assert "crypto/algorithm/mlkem768x25519-sha256" in refs


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
