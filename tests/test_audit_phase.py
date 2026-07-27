# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Focused contracts for the artifact audit's self-scan assertions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.audit_phase import (
    EXPECTED_LIVE_TARGETS,
    EXPECTED_SELF_SCAN_STATUSES,
    AuditResult,
    _check_phase_5_self_scan,
)

_TARGET_BY_FILE = dict(zip(EXPECTED_SELF_SCAN_STATUSES, EXPECTED_LIVE_TARGETS, strict=True))


def _write_self_scan(
    root: Path,
    *,
    statuses: dict[str, str] | None = None,
) -> Path:
    self_scan_dir = root / "phase-5-self-scan"
    self_scan_dir.mkdir()
    actual_statuses = statuses or EXPECTED_SELF_SCAN_STATUSES
    for filename, status in actual_statuses.items():
        payload = {
            "target": {"host": _TARGET_BY_FILE.get(filename, "unexpected.example")},
            "scan": {"status": status},
        }
        (self_scan_dir / filename).write_text(json.dumps(payload), encoding="utf-8")
    return self_scan_dir


def test_phase_5_accepts_exact_files_targets_and_statuses(tmp_path: Path) -> None:
    _write_self_scan(tmp_path)
    result = AuditResult()

    _check_phase_5_self_scan(tmp_path, result)

    assert result.failed == []
    assert len(result.passed) == 1


@pytest.mark.parametrize("wrong_status", ["completed", "failed"])
def test_phase_5_rejects_wrong_negative_control_status(tmp_path: Path, wrong_status: str) -> None:
    statuses = {**EXPECTED_SELF_SCAN_STATUSES, "tls12.json": wrong_status}
    _write_self_scan(tmp_path, statuses=statuses)
    result = AuditResult()

    _check_phase_5_self_scan(tmp_path, result)

    assert any("tls12.json" in failure for failure in result.failed)
    assert any("expected tls_handshake_failed" in failure for failure in result.failed)


def test_phase_5_rejects_missing_and_unexpected_files(tmp_path: Path) -> None:
    statuses = dict(EXPECTED_SELF_SCAN_STATUSES)
    statuses.pop("google.json")
    statuses["seventh.json"] = "completed"
    _write_self_scan(tmp_path, statuses=statuses)
    result = AuditResult()

    _check_phase_5_self_scan(tmp_path, result)

    assert any("google.json" in failure for failure in result.failed)
    assert any("seventh.json" in failure for failure in result.failed)
