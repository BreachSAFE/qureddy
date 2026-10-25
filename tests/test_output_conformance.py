# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the output conformance harness."""

from __future__ import annotations

import json
import shutil
from hashlib import sha256
from pathlib import Path

import pytest
import typer
from scripts.validate_output_bundle import _rich_contains_value, validate_bundle

from qureddy.cli._render import _render_bundle
from tests._cbom_fixtures import _build_result


def _write_bundle(directory: Path, result=None) -> None:
    """Emit all supported projections from the canonical test ScanResult."""
    result = result or _build_result()
    finding = result.findings[0].model_copy(update={"runtime": "openssl"})
    _render_bundle(
        result.model_copy(update={"findings": (finding,)}),
        directory,
        reproducible=True,
        compact=False,
    )


def test_bundle_validator_accepts_canonical_projection_bundle(tmp_path: Path) -> None:
    """A real renderer bundle passes all projection and manifest checks."""
    _write_bundle(tmp_path)

    result = validate_bundle(tmp_path, "tls", "example.com")

    assert "findings=1" in result
    assert "jsonl_records=2" in result
    assert "sarif_results=not-requested" in result


def test_bundle_with_certificate_publishes_each_artifact_once(tmp_path: Path) -> None:
    """Certificate evidence must not make the atomic bundle commit repeat a file."""
    result = _build_result()
    evidence = result.evidence[0].model_copy(
        update={"certificate_pem": "-----BEGIN CERTIFICATE-----\nleaf"}
    )

    _write_bundle(tmp_path, result.model_copy(update={"evidence": (evidence,)}))

    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    names = [artifact["name"] for artifact in manifest["artifacts"]]
    assert names.count("certificate.pem") == 1
    assert (tmp_path / "certificate.pem").is_file()


def test_bundle_validator_rejects_manifest_that_omits_artifacts(tmp_path: Path) -> None:
    """A complete bundle manifest must enumerate every file on disk."""
    _write_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = []
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="artifact list does not match bundle"):
        validate_bundle(tmp_path, "tls", "example.com")


def test_bundle_validator_rejects_markdown_identity_drift(tmp_path: Path) -> None:
    """A digest-consistent Markdown mutation cannot bypass canonical parity."""
    _write_bundle(tmp_path)
    scan_markdown = tmp_path / "scan.md"
    scan_markdown.write_text(
        scan_markdown.read_text(encoding="utf-8").replace("scan-test", "different-scan"),
        encoding="utf-8",
    )
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        if artifact["name"] == "scan.md":
            data = scan_markdown.read_bytes()
            artifact["size"] = len(data)
            artifact["sha256"] = sha256(data).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match=r"scan\.md: missing canonical scan_id"):
        validate_bundle(tmp_path, "tls", "example.com")


def test_bundle_rollback_failure_preserves_diagnostic_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed restore returns a controlled error and preserves the backup."""
    _write_bundle(tmp_path)
    original_replace = Path.replace
    install_failed = False

    def fail_install_and_rollback(self: Path, target: Path) -> Path:
        nonlocal install_failed
        if self.parent.name.startswith(".qureddy-bundle-") and self.name == "scan.md":
            install_failed = True
            raise OSError(5, "simulated install failure")
        if install_failed and self.parent.name.startswith(".qureddy-backup-"):
            raise OSError(5, "simulated rollback failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_install_and_rollback)
    try:
        with pytest.raises(typer.Exit) as failure:
            _render_bundle(_build_result(), tmp_path, reproducible=True, compact=False)
        assert failure.value.exit_code == 70
        assert any(path.name.startswith(".qureddy-backup-") for path in tmp_path.iterdir())
    finally:
        for path in tmp_path.glob(".qureddy-backup-*"):
            shutil.rmtree(path, ignore_errors=True)


def test_bundle_install_failure_removes_partial_public_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A first-run failure after partial publication leaves no artifacts."""
    original_replace = Path.replace

    def fail_after_five_installs(self: Path, target: Path) -> Path:
        if self.parent.name.startswith(".qureddy-bundle-") and self.name == "cbom.md":
            raise OSError(28, "simulated install failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_after_five_installs)
    with pytest.raises(typer.Exit) as failure:
        _render_bundle(_build_result(), tmp_path, reproducible=True, compact=False)

    assert failure.value.exit_code == 70
    assert not [path for path in tmp_path.iterdir() if path.is_file()]
    assert not list(tmp_path.glob(".qureddy-backup-*"))


def test_bundle_validator_rejects_jsonl_finding_drift(tmp_path: Path) -> None:
    """A changed JSONL finding cannot silently diverge from canonical JSON."""
    _write_bundle(tmp_path)
    jsonl_path = tmp_path / "scan.jsonl"
    records = [json.loads(line) for line in jsonl_path.read_text().splitlines()]
    records[0]["template-id"] = "tls.fabricated.rule"
    jsonl_path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records)
    )

    with pytest.raises(ValueError, match="JSONL finding identity drift"):
        validate_bundle(tmp_path, "tls", "example.com")


def test_bundle_validator_rejects_cbom_status_drift(tmp_path: Path) -> None:
    """A schema-valid CBOM cannot contradict canonical scan status (#922)."""
    _write_bundle(tmp_path)
    cbom_path = tmp_path / "scan.cdx.json"
    payload = json.loads(cbom_path.read_text())
    for property_ in payload["metadata"]["properties"]:
        if property_["name"] == "qureddy:scan.status":
            property_["value"] = "fabricated-status"
            break
    cbom_path.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match="CBOM summary field drift: status"):
        validate_bundle(tmp_path, "tls", "example.com")


def test_bundle_validator_rejects_unexpected_cbom_failure_category(tmp_path: Path) -> None:
    """A CBOM cannot invent a conditional failure field absent from JSON (#922)."""
    _write_bundle(tmp_path)
    cbom_path = tmp_path / "scan.cdx.json"
    payload = json.loads(cbom_path.read_text())
    payload["metadata"]["properties"].append(
        {"name": "qureddy:scan.failure_category", "value": "timeout"}
    )
    cbom_path.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match="CBOM summary field drift: failure_category"):
        validate_bundle(tmp_path, "tls", "example.com")


def test_bundle_validator_preserves_repeated_cbom_nist_levels(tmp_path: Path) -> None:
    """Repeated CycloneDX properties remain an ordered canonical level list (#922)."""
    result = _build_result()
    result = result.model_copy(
        update={
            "summary": result.summary.model_copy(
                update={
                    "nist_quantum_security_levels": (0, 3, 5),
                    "nist_quantum_security_level_max": 5,
                }
            )
        }
    )
    _write_bundle(tmp_path, result)
    cbom_path = tmp_path / "scan.cdx.json"
    payload = json.loads(cbom_path.read_text())
    properties = payload["metadata"]["properties"]
    properties.remove(
        next(
            item
            for item in properties
            if item["name"] == "qureddy:scan.nist_quantum_security_level" and item["value"] == "3"
        )
    )
    cbom_path.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match="CBOM summary field drift: nist_quantum_security_levels"):
        validate_bundle(tmp_path, "tls", "example.com")


def test_rich_validator_accepts_wrapped_crypto_value() -> None:
    """Column wrapping inside a crypto token must not look like data loss (#921)."""
    wrapped = "ECDHE-ECDSA-AE CWE-757 S128-SHA"

    assert _rich_contains_value(wrapped, "ECDHE-ECDSA-AES128-SHA")


def test_bundle_validator_accepts_optional_sarif_envelope(tmp_path: Path) -> None:
    """The fifth-format gate validates a supplied SARIF 2.1.0 artifact."""
    _write_bundle(tmp_path)
    (tmp_path / "scan.sarif.json").write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {"driver": {"name": "QuReddy"}},
                        "results": [{"ruleId": "tls.hybrid.negotiated_pq"}],
                    }
                ],
            }
        )
    )

    result = validate_bundle(tmp_path, "tls", "example.com", tmp_path / "scan.sarif.json")

    assert "sarif_results=1" in result
