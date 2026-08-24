# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the line-oriented finding projection."""

from __future__ import annotations

from qureddy.core.finding_identity import finding_hash
from qureddy.core.models import Finding, ScanTarget


def _target(*, sni: str | None = "example.com") -> ScanTarget:
    return ScanTarget(
        scheme="tls",
        host="Example.COM",
        port=443,
        sni=sni,
        original_input="example.com",
        locator="tls://Example.COM:443",
    )


def _finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "rule_id": "tls-weak-cipher",
        "id": "finding-1",
        "asset_id": "asset-1",
        "evidence_ids": ("evidence-1",),
        "title": "Weak cipher",
        "description": "A weak cipher was negotiated.",
        "severity": "high",
        "finding_type": "cipher",
        "protocol": "tls",
        "protocol_version": "TLSv1.2",
        "algorithm": "AES-128-CBC",
        "readiness": "classically_weak",
        "confidence": "high",
    }
    values.update(overrides)
    return Finding(**values)


def test_finding_hash_is_stable_and_semantic() -> None:
    target = _target()
    finding = _finding()
    assert finding_hash(target, finding) == finding_hash(target, finding)
    assert finding_hash(target, finding) != finding_hash(_target(sni="other.example"), finding)
    assert finding_hash(target, finding) != finding_hash(
        target, _finding(protocol_version="TLSv1.3")
    )
