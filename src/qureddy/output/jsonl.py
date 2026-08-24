# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Osmedeus/nuclei-compatible JSONL output adapter."""

from __future__ import annotations

import ipaddress
import json
import operator
import sys
from typing import IO, TYPE_CHECKING, Any

from qureddy.core.finding_identity import finding_hash

if TYPE_CHECKING:
    from qureddy.core.models import Finding, ScanResult


def _ip_or_none(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return host


def _nuclei_type(scheme: str) -> str:
    return {"tls": "ssl", "ssh": "ssh"}[scheme]


def finding_record(result: ScanResult, finding: Finding) -> dict[str, Any]:
    """Project one domain finding into the line-oriented wire contract."""
    extracted = [
        value
        for value in (
            finding.algorithm,
            finding.protocol_version,
            finding.negotiated_group,
        )
        if value is not None
    ]
    return {
        "template-id": finding.rule_id,
        "type": _nuclei_type(result.target.scheme),
        "host": f"{result.target.host}:{result.target.port}",
        "matched-at": f"{result.target.host}:{result.target.port}",
        "url": result.target.locator,
        "port": result.target.port,
        "ip": _ip_or_none(result.target.host),
        "timestamp": result.scan.completed_at.isoformat(),
        "matcher-name": next(iter(extracted), None),
        "extracted-results": extracted,
        "finding_hash": finding_hash(result.target, finding),
        "info": {
            "name": finding.title,
            "severity": finding.severity.value,
            "description": finding.description,
            "tags": ["pqc", result.scan.scanner_name, finding.finding_type],
            "classification": {
                "oid": finding.oid,
                "nist-quantum-security-level": finding.nist_quantum_security_level,
            },
            "metadata": {
                "finding_type": finding.finding_type,
                "readiness": finding.readiness.value,
                "confidence": finding.confidence.value,
                "primitive": finding.primitive,
                "algorithm": finding.algorithm,
                "protocol": finding.protocol,
                "protocol_version": finding.protocol_version,
                "negotiated_group": finding.negotiated_group,
                "nist_quantum_security_level": finding.nist_quantum_security_level,
                "key_size": finding.key_size,
                "parameter_set_identifier": finding.parameter_set_identifier,
                "oid": finding.oid,
                "bom_ref": finding.bom_ref,
                "scan_id": result.scan.scan_id,
                "scanner_version": result.scan.scanner_version,
            },
        },
    }


def render_jsonl(result: ScanResult, stream: IO[str] | None = None) -> None:
    """Emit one compact, deterministic JSON object per finding."""
    target = stream if stream is not None else sys.stdout
    records = [finding_record(result, finding) for finding in result.findings]
    for record in sorted(records, key=operator.itemgetter("finding_hash")):
        json.dump(record, target, ensure_ascii=True, separators=(",", ":"))
        target.write("\n")
