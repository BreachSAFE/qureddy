#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Validate the correlated output bundle emitted by one QuReddy scan.

One canonical ``ScanResult`` is projected into JSON, JSONL, Rich, and CBOM.
This validator checks the machine contracts, the visible Rich contract, and
the independent CycloneDX 1.7 oracle without re-scanning or re-interpreting
the endpoint.  SARIF is accepted as an optional fifth artifact once a SARIF
renderer exists; it is deliberately not fabricated by this tool.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tests.conformance.harness import official_errors, semantic_errors  # noqa: E402

_REQUIRED_ARTIFACTS = ("scan.json", "scan.cdx.json", "scan.jsonl", "scan.rich.txt")
_MIN_RICH_FRAGMENT_LENGTH = 3
_SUMMARY_FIELDS = (
    "readiness",
    "nist_quantum_security_levels",
    "nist_quantum_security_level_max",
    "finding_count",
    "failure_category",
)


def _parse_args() -> argparse.Namespace:
    """Parse one output-bundle validation request."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--sarif",
        type=Path,
        help="Optional SARIF 2.1.0 artifact to validate when a renderer exists.",
    )
    return parser.parse_args()


def _read_json(path: Path) -> dict[str, Any]:
    """Read one JSON object and fail with an artifact-specific message."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}: top level must be an object")
    return payload


def _finding_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    """Return the cross-format identity fields for one canonical finding."""
    return (
        finding.get("rule_id"),
        finding.get("protocol_version"),
        finding.get("algorithm"),
        finding.get("runtime"),
        finding.get("severity"),
        tuple(finding.get("cwe_ids") or ()),
    )


def _jsonl_findings(
    path: Path, scan: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse JSONL and return its trailing summary plus finding records."""
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name}:{line_number}: invalid JSONL: {exc}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"{path.name}:{line_number}: record must be an object")
        records.append(record)
    if not records:
        raise ValueError("scan.jsonl: no records")
    summary = records[-1]
    if summary.get("type") != "scan_summary":
        raise ValueError("scan.jsonl: final record is not scan_summary")
    if summary.get("scan_id") != scan.get("scan_id"):
        raise ValueError("scan.jsonl: summary scan_id does not match scan.json")
    if summary.get("status") != scan.get("status"):
        raise ValueError("scan.jsonl: summary status does not match scan.json")
    findings = records[:-1]
    for record in findings:
        metadata = record.get("info", {}).get("metadata", {})
        if metadata.get("scan_id") != scan.get("scan_id"):
            raise ValueError("scan.jsonl: finding scan_id does not match scan.json")
    return summary, findings


def _validate_sarif(path: Path, findings: list[Any]) -> int:
    """Validate the minimum SARIF 2.1.0 envelope and result shape."""
    payload = _read_json(path)
    if payload.get("version") != "2.1.0":
        raise ValueError("SARIF version must be 2.1.0")
    runs = payload.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF runs must be a non-empty array")
    result_count = 0
    result_rule_ids: list[str] = []
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("tool", {}).get("driver"), dict):
            raise ValueError("SARIF run is missing tool.driver")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("SARIF run results must be an array")
        result_count += len(results)
        for result in results:
            if not isinstance(result, dict) or not isinstance(result.get("ruleId"), str):
                raise ValueError("SARIF result is missing ruleId")
            result_rule_ids.append(result["ruleId"])
    expected_rule_ids = sorted(
        finding["rule_id"] for finding in findings if isinstance(finding, dict)
    )
    if sorted(result_rule_ids) != expected_rule_ids:
        raise ValueError("SARIF finding identity drift")
    return result_count


def _load_canonical(run_dir: Path, scanner: str, target: str) -> dict[str, Any]:
    """Load and validate the native JSON document's identity and counts."""
    canonical = _read_json(run_dir / "scan.json")
    scan = canonical.get("scan")
    target_data = canonical.get("target")
    if not isinstance(scan, dict) or not isinstance(target_data, dict):
        raise ValueError("scan.json: scan and target must be objects")
    if scan.get("scanner_name") != scanner:
        raise ValueError("scan.json: scanner identity mismatch")
    if target_data.get("original_input") != target:
        raise ValueError("scan.json: target identity mismatch")
    if not isinstance(scan.get("scan_id"), str) or not scan["scan_id"]:
        raise ValueError("scan.json: scan_id is missing")
    summary = canonical.get("summary")
    findings = canonical.get("findings")
    if not isinstance(summary, dict) or not isinstance(findings, list):
        raise ValueError("scan.json: summary and findings must be present")
    if summary.get("finding_count") != len(findings):
        raise ValueError("scan.json: finding_count does not match findings")
    return canonical


def _validate_cbom(run_dir: Path) -> dict[str, Any]:
    """Validate CBOM bytes with the pinned schema and semantic oracle."""
    cbom = _read_json(run_dir / "scan.cdx.json")
    errors = official_errors(cbom) + semantic_errors(cbom)
    if errors:
        raise ValueError(f"scan.cdx.json: {' | '.join(errors)}")
    if cbom.get("bomFormat") != "CycloneDX" or cbom.get("specVersion") != "1.7":
        raise ValueError("scan.cdx.json: expected CycloneDX 1.7")
    return cbom


def _validate_cbom_identity(cbom: dict[str, Any], scanner: str, target: str) -> None:
    """Ensure CBOM metadata identifies the same scan target and scanner."""
    properties = {
        item.get("name"): item.get("value")
        for item in cbom.get("metadata", {}).get("properties", [])
        if isinstance(item, dict)
    }
    if properties.get("qureddy:scan.scanner_name") != scanner:
        raise ValueError("scan.cdx.json: scanner identity mismatch")
    if properties.get("qureddy:target.original_input") != target:
        raise ValueError("scan.cdx.json: target identity mismatch")


def _validate_jsonl_parity(
    run_dir: Path, scan: dict[str, Any], summary: dict[str, Any], findings: list[Any]
) -> int:
    """Validate JSONL correlation and parity with native JSON findings."""
    jsonl_summary, jsonl_findings = _jsonl_findings(run_dir / "scan.jsonl", scan)
    if jsonl_summary.get("status") != scan.get("status"):
        raise ValueError("JSONL summary field drift: status")
    for field in _SUMMARY_FIELDS:
        if jsonl_summary.get(field) != summary.get(field):
            raise ValueError(f"JSONL summary field drift: {field}")
    expected_keys = sorted(
        _finding_key(finding) for finding in findings if isinstance(finding, dict)
    )
    actual_keys = sorted(
        _finding_key(
            {
                "rule_id": record.get("template-id"),
                "protocol_version": record.get("info", {})
                .get("metadata", {})
                .get("protocol_version"),
                "algorithm": record.get("info", {}).get("metadata", {}).get("algorithm"),
                "runtime": record.get("info", {}).get("metadata", {}).get("runtime"),
                "severity": record.get("info", {}).get("severity"),
                "cwe_ids": record.get("info", {}).get("metadata", {}).get("cwe_ids"),
            }
        )
        for record in jsonl_findings
    )
    if actual_keys != expected_keys:
        raise ValueError("JSONL finding identity drift")
    return len(jsonl_findings) + 1


def _validate_rich(run_dir: Path, scanner: str, findings: list[Any]) -> None:
    """Validate required Rich sections and visible finding identity fields."""
    rich = (run_dir / "scan.rich.txt").read_text(encoding="utf-8")
    if not rich.startswith("QuReddy"):
        raise ValueError("Rich output does not carry the QuReddy header")
    if scanner.upper() not in rich.upper():
        raise ValueError("Rich output does not identify the scanner")
    missing_labels = [
        label for label in ("Scan details", "Findings", "Run details") if label not in rich
    ]
    if missing_labels:
        raise ValueError(f"Rich output missing sections: {', '.join(missing_labels)}")
    compact_rich = re.sub(r"\s+", "", rich)
    for field in ("status", "findings", "attempts"):
        if field not in rich:
            raise ValueError(f"Rich output missing field label: {field}")
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        for value in (finding.get("rule_id"), finding.get("algorithm")):
            if value is not None and not _rich_contains_value(compact_rich, value):
                raise ValueError(f"Rich output dropped finding value: {value}")


def _rich_contains_value(compact_rich: str, value: str) -> bool:
    """Match a value despite Rich wrapping a table cell between characters."""
    compact_value = re.sub(r"\s+", "", value)
    if compact_value in compact_rich:
        return True
    fragments = [
        fragment
        for fragment in re.split(r"[-_]", value)
        if len(fragment) >= _MIN_RICH_FRAGMENT_LENGTH
    ]
    return len(fragments) > 1 and all(fragment in compact_rich for fragment in fragments)


def validate_bundle(run_dir: Path, scanner: str, target: str, sarif: Path | None = None) -> str:
    """Validate all supported projections from one scan bundle."""
    missing = [name for name in _REQUIRED_ARTIFACTS if not (run_dir / name).is_file()]
    if missing:
        raise ValueError(f"missing artifacts: {', '.join(missing)}")

    canonical = _load_canonical(run_dir, scanner, target)
    scan = canonical["scan"]
    summary = canonical["summary"]
    findings = canonical["findings"]
    cbom = _validate_cbom(run_dir)
    _validate_cbom_identity(cbom, scanner, target)
    jsonl_count = _validate_jsonl_parity(run_dir, scan, summary, findings)
    _validate_rich(run_dir, scanner, findings)

    sarif_count = "not-requested"
    if sarif is not None:
        sarif_count = str(_validate_sarif(sarif, findings))
    return (
        f"status={scan['status']} findings={len(findings)} "
        f"evidence={len(canonical.get('evidence', []))} "
        f"components={len(cbom.get('components', []))} "
        f"jsonl_records={jsonl_count} sarif_results={sarif_count}"
    )


def main() -> int:
    """Run the fail-closed bundle validator."""
    args = _parse_args()
    try:
        print(validate_bundle(args.run_dir, args.scanner, args.target, args.sarif))
    except (OSError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
