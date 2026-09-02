# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Cross-format regression coverage for cryptographic classification parity."""

from __future__ import annotations

import io
import json
from unittest.mock import patch

from qureddy.core.algorithm_profile import classify_key_exchange
from qureddy.core.models import Evidence, ObservationType, ScanResult
from qureddy.core.policy import classify_evidence
from qureddy.core.targets import parse_ssh_target
from qureddy.output.cbom import render_cbom
from qureddy.output.json import render_json
from qureddy.output.jsonl import render_jsonl
from qureddy.scanners.ssh.classify import classify_offered_algorithm
from qureddy.scanners.ssh.probe import SSHOffer
from qureddy.scanners.ssh.scanner import scan_ssh
from tests._cbom_fixtures import _build_result


def _github_like_ssh_result() -> ScanResult:
    """Return a deterministic scan result shaped like GitHub's current SSH offer."""
    offer = SSHOffer(
        server_banner="SSH-2.0-babeld",
        kex_algorithms=("sntrup761x25519-sha512", "curve25519-sha256"),
        host_key_algorithms=("ssh-ed25519",),
        ciphers=("chacha20-poly1305@openssh.com",),
        macs=("hmac-sha2-256-etm@openssh.com",),
    )
    with patch("qureddy.scanners.ssh.scanner.read_kexinit_offer", return_value=offer):
        return scan_ssh(parse_ssh_target("github.com"), timeout_seconds=1)


def test_key_exchange_classifier_rejects_embedded_known_tokens() -> None:
    """Keep server-controlled names from spoofing a recognized classical group."""
    assert classify_key_exchange("notx25519evil") is None
    assert classify_key_exchange("notcurve25519evil") is None


def test_x25519_classification_matches_json_jsonl_and_cbom() -> None:
    """Project one classified finding identically across every machine format."""
    base = _build_result()
    evidence = Evidence(
        id="evidence-x25519",
        asset_id=base.assets[0].id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        negotiated_group="X25519",
    )
    finding = classify_evidence(base.assets[0], [evidence])[0]
    result = base.model_copy(update={"evidence": (evidence,), "findings": (finding,)})

    json_stream = io.StringIO()
    render_json(result, json_stream)
    json_finding = json.loads(json_stream.getvalue())["findings"][0]

    jsonl_stream = io.StringIO()
    render_jsonl(result, jsonl_stream)
    jsonl_finding = json.loads(jsonl_stream.getvalue().splitlines()[0])
    jsonl_metadata = jsonl_finding["info"]["metadata"]

    cbom_stream = io.StringIO()
    render_cbom(result, cbom_stream, reproducible=True)
    cbom = json.loads(cbom_stream.getvalue())
    cbom_properties = next(
        component["cryptoProperties"]["algorithmProperties"]
        for component in cbom["components"]
        if component["bom-ref"] == "crypto/algorithm/x25519"
    )

    expected = ("key-agree", 0)
    assert (json_finding["primitive"], json_finding["nist_quantum_security_level"]) == expected
    assert (
        jsonl_metadata["primitive"],
        jsonl_metadata["nist_quantum_security_level"],
    ) == expected
    assert (
        cbom_properties["primitive"],
        cbom_properties["nistQuantumSecurityLevel"],
    ) == expected


def test_ssh_named_evidence_exposes_algorithm_classification_in_json() -> None:
    """Expose each exact SSH offer to native-JSON inventory consumers (#645)."""
    result = _github_like_ssh_result()
    stream = io.StringIO()
    render_json(result, stream)
    evidence = {
        (item["evidence_type"], item["algorithm"]): item
        for item in json.loads(stream.getvalue())["evidence"]
        if item["algorithm"] is not None
    }

    assert (
        evidence[("ssh.kex", "sntrup761x25519-sha512")]["primitive"],
        evidence[("ssh.kex", "sntrup761x25519-sha512")]["parameter_set_identifier"],
        evidence[("ssh.kex", "sntrup761x25519-sha512")]["nist_quantum_security_level"],
    ) == ("kem", "sntrup761", 2)
    assert (
        evidence[("ssh.kex", "curve25519-sha256")]["primitive"],
        evidence[("ssh.kex", "curve25519-sha256")]["nist_quantum_security_level"],
    ) == ("key-agree", 0)
    assert (
        evidence[("ssh.hostkey", "ssh-ed25519")]["primitive"],
        evidence[("ssh.hostkey", "ssh-ed25519")]["nist_quantum_security_level"],
    ) == ("signature", 0)
    assert evidence[("ssh.cipher", "chacha20-poly1305@openssh.com")]["primitive"] == "ae"
    assert evidence[("ssh.mac", "hmac-sha2-256-etm@openssh.com")]["primitive"] == "mac"

    cbom_stream = io.StringIO()
    render_cbom(result, cbom_stream, reproducible=True)
    cbom_profiles = {
        component["name"]: component["cryptoProperties"]["algorithmProperties"]
        for component in json.loads(cbom_stream.getvalue())["components"]
        if component.get("cryptoProperties", {}).get("assetType") == "algorithm"
    }
    for (_evidence_type, algorithm), item in evidence.items():
        assert item["primitive"] == cbom_profiles[algorithm]["primitive"]
        assert item["nist_quantum_security_level"] == cbom_profiles[algorithm].get(
            "nistQuantumSecurityLevel"
        )


def test_ssh_classical_alternative_exposes_its_representative_algorithm() -> None:
    """Keep an exact finding's algorithm identity alongside its classification (#645)."""
    finding = next(
        item
        for item in _github_like_ssh_result().findings
        if item.rule_id == "ssh.kex.classical_alternative"
    )

    assert finding.algorithm == "curve25519-sha256"
    assert finding.negotiated_group == finding.algorithm


def test_unknown_ssh_offer_keeps_identity_without_fabricated_classification() -> None:
    """Preserve unknown names while leaving their classification explicitly null (#645)."""
    offer = SSHOffer(
        server_banner="SSH-2.0-test",
        kex_algorithms=("future-kex@example.com",),
        host_key_algorithms=("future-signature@example.com",),
        ciphers=(),
        macs=(),
    )
    with patch("qureddy.scanners.ssh.scanner.read_kexinit_offer", return_value=offer):
        result = scan_ssh(parse_ssh_target("test.invalid"), timeout_seconds=1)
    evidence = next(item for item in result.evidence if item.evidence_type == "ssh.kex")

    assert evidence.algorithm == "future-kex@example.com"
    assert evidence.primitive is None
    assert evidence.parameter_set_identifier is None
    assert evidence.nist_quantum_security_level is None

    host_key = next(item for item in result.evidence if item.evidence_type == "ssh.hostkey")
    assert host_key.algorithm == "future-signature@example.com"
    assert host_key.primitive is None
    cbom_stream = io.StringIO()
    render_cbom(result, cbom_stream, reproducible=True)
    component = next(
        item
        for item in json.loads(cbom_stream.getvalue())["components"]
        if item["name"] == "future-signature@example.com"
    )
    assert component["cryptoProperties"] == {"assetType": "algorithm"}


def test_non_algorithm_ssh_evidence_type_has_no_classification() -> None:
    """Keep server identity and posture evidence outside the algorithm inventory."""
    assert classify_offered_algorithm("ssh.server", "OpenSSH") is None
