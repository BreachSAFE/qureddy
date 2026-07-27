# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Policy contracts for hosted CI topology."""

from __future__ import annotations

from pathlib import Path

CI_WORKFLOW = Path(".github/workflows/ci.yml")
LIVE_ONLY_IF = (
    "if: ${{ github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' }}"
)


def test_public_network_probes_are_scheduled_or_manual_only() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    live_phase = workflow.split("  phase-4-live:", 1)[1].split("  phase-5-self-scan:", 1)[0]
    self_scan = workflow.split("  phase-5-self-scan:", 1)[1].split("  phase-6-build:", 1)[0]

    assert "  schedule:" in workflow
    assert LIVE_ONLY_IF in live_phase
    assert LIVE_ONLY_IF in self_scan
    assert "scan ssh github.com" in self_scan


def test_blocking_package_install_smoke_is_hermetic() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    packaging = workflow.split("  packaging-install:", 1)[1]

    assert "scan ssh 127.0.0.1:1" in packaging
    assert "scan ssh github.com" not in packaging


def test_legacy_ci_uses_the_release_gate_secret_scanner() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    assert "python scripts/run_secret_scan.py" in workflow
    assert "gitleaks/gitleaks-action@" not in workflow
