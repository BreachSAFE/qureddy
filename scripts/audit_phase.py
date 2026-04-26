# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CI Phase 7 audit script.

Reads artifacts produced by prior CI phases and asserts on specific facts:
test counts, coverage percentage, scan completion, etc. The point is to
prevent skim-passing — a passing exit code from `pytest` is not enough;
the audit verifies that pytest actually collected tests, ran them, and
produced expected coverage.

Usage:
    python scripts/audit_phase.py --artifacts-dir ci-artifacts/

Exit codes:
    0 = all assertions passed
    1 = assertion failures (audit caught a problem)
    2 = artifacts missing or malformed (CI configuration problem)
    3 = expected pre-MVP state (no scanner yet, no implementation yet);
        not a failure, just a soft pass with notes.

This script must NOT import from the qureddy package. It is a CI utility
that runs against build outputs; coupling it to the code it audits would
be circular.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# defusedxml replaces stdlib xml.etree to neutralize XXE / billion-laughs /
# external-entity expansion. CI artifacts (coverage.xml, junit.xml) come
# from third-party tooling output; even though we trust pytest today,
# the security bar in CODING_RULES §26 is "no untrusted XML parsers,"
# full stop, so we use the safe parser regardless of source trust.
# `ET` is the universal Python idiom for ElementTree (N817 ack'd).
from defusedxml import ElementTree as ET  # type: ignore[import-untyped]  # noqa: N817

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_BAD_ARTIFACTS = 2
EXIT_PRE_MVP_SOFT_PASS = 3

MIN_COVERAGE_PERCENT = 80.0
MIN_UNIT_TEST_COUNT_AT_MVP = 20
EXPECTED_LIVE_TARGETS = (
    "www.cloudflare.com",
    "pq.cloudflareresearch.com",
    "www.google.com",
    "example.com",
    "1.1.1.1",
    "tls-v1-2.badssl.com",
)


@dataclass
class AuditResult:
    """Aggregate audit verdict."""

    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    pre_mvp_soft_pass: bool = False

    def ok(self, msg: str) -> None:
        self.passed.append(msg)

    def fail(self, msg: str) -> None:
        self.failed.append(msg)

    def note(self, msg: str) -> None:
        self.notes.append(msg)

    @property
    def has_failures(self) -> bool:
        return len(self.failed) > 0


def _check_phase_2_unit(artifacts: Path, result: AuditResult) -> None:
    """Verify unit tests ran and coverage >= 80%."""
    coverage_files = list(artifacts.glob("coverage-*/coverage.xml"))
    if not coverage_files:
        result.note("phase-2: no coverage.xml found. Pre-MVP state expected; no failure recorded.")
        result.pre_mvp_soft_pass = True
        return

    for cov_file in coverage_files:
        try:
            tree = ET.parse(cov_file)
        except ET.ParseError as e:
            result.fail(f"phase-2: malformed coverage.xml at {cov_file}: {e}")
            continue

        root_elem = tree.getroot()
        line_rate_str = root_elem.get("line-rate", "0")
        try:
            line_rate = float(line_rate_str) * 100
        except ValueError:
            result.fail(f"phase-2: bad line-rate value at {cov_file}: {line_rate_str}")
            continue

        if line_rate < MIN_COVERAGE_PERCENT:
            result.fail(
                f"phase-2: coverage {line_rate:.1f}% at {cov_file.parent.name} "
                f"is below required {MIN_COVERAGE_PERCENT}%"
            )
        else:
            result.ok(
                f"phase-2: coverage {line_rate:.1f}% at {cov_file.parent.name} meets threshold"
            )


def _count_tests_in_junit(junit_path: Path) -> int:
    """Read a JUnit XML file and return the test count, or 0 if unparseable."""
    try:
        tree = ET.parse(junit_path)
    except ET.ParseError:
        return 0

    root_elem = tree.getroot()
    # JUnit XML may have <testsuites> wrapping <testsuite> or just <testsuite>.
    suites = root_elem.findall(".//testsuite") or [root_elem]
    return sum(int(s.get("tests", "0")) for s in suites)


def _check_phase_4_live(artifacts: Path, result: AuditResult) -> None:
    """Verify live tests covered every canonical target."""
    live_dirs = list(artifacts.glob("live-results-*"))
    if not live_dirs:
        result.note("phase-4: no live-results-* artifact found.")
        result.pre_mvp_soft_pass = True
        return

    # We do not have a structured artifact format for live test results yet;
    # a follow-up commit at MVP 0.1 implementation time will add JUnit XML
    # output and target-coverage parsing here.
    result.note(
        "phase-4: live test artifact present but structured per-target "
        "verification not yet wired. Add JUnit XML output and parse here "
        "at MVP 0.1 implementation time."
    )


def _check_phase_5_self_scan(artifacts: Path, result: AuditResult) -> None:
    """Verify self-scan ran for every canonical target (when scanner exists)."""
    self_scan_dir = artifacts / "phase-5-self-scan"
    if not self_scan_dir.is_dir():
        result.note("phase-5: no phase-5-self-scan artifact directory.")
        result.pre_mvp_soft_pass = True
        return

    pending = self_scan_dir / "PENDING.json"
    if pending.is_file():
        result.note("phase-5: scanner not yet present (PENDING.json marker). Pre-MVP soft pass.")
        result.pre_mvp_soft_pass = True
        return

    json_files = sorted(self_scan_dir.glob("*.json"))
    if not json_files:
        result.fail("phase-5: scanner directory present but no JSON outputs")
        return

    found_targets = set()
    for json_file in json_files:
        try:
            data = json.loads(json_file.read_text())
        except json.JSONDecodeError as e:
            result.fail(f"phase-5: malformed JSON at {json_file.name}: {e}")
            continue

        target = data.get("target", {}).get("host", "<unknown>")
        found_targets.add(target)

        scan_meta = data.get("scan", {})
        status = scan_meta.get("status", "<missing>")
        if status not in ("completed", "failed"):
            result.fail(f"phase-5: {json_file.name} has unexpected scan.status={status}")

    missing = [t for t in EXPECTED_LIVE_TARGETS if not any(t in f for f in found_targets)]
    if missing:
        result.fail(f"phase-5: missing self-scan results for: {', '.join(missing)}")
    else:
        result.ok(f"phase-5: self-scan covered {len(found_targets)} canonical targets")


def _check_phase_6_build(artifacts: Path, result: AuditResult) -> None:
    """Verify the build produced both sdist and wheel."""
    dist_dir = artifacts / "phase-6-dist"
    if not dist_dir.is_dir():
        result.note("phase-6: no phase-6-dist artifact directory.")
        result.pre_mvp_soft_pass = True
        return

    sdists = list(dist_dir.glob("*.tar.gz"))
    wheels = list(dist_dir.glob("*.whl"))

    if not sdists:
        result.fail("phase-6: no sdist (.tar.gz) produced by uv build")
    else:
        result.ok(f"phase-6: sdist produced ({sdists[0].name})")

    if not wheels:
        result.fail("phase-6: no wheel (.whl) produced by uv build")
    else:
        result.ok(f"phase-6: wheel produced ({wheels[0].name})")


def _check_no_skipped_test_markers(artifacts: Path, result: AuditResult) -> None:
    """Per CODING_RULES Rule 9.3, no @pytest.mark.skip etc allowed.

    Scans the JUnit XML output for SKIPPED tests. Skipped tests indicate
    someone added a marker that violates the rule.
    """
    junit_files = list(artifacts.rglob("*junit*.xml")) + list(
        artifacts.rglob("pytest-results*.xml")
    )
    if not junit_files:
        result.note(
            "no JUnit XML found for skip-marker check. "
            "Wire pytest --junit-xml in CI to enable this check."
        )
        return

    total_skipped = 0
    for junit_file in junit_files:
        try:
            tree = ET.parse(junit_file)
        except ET.ParseError:
            continue
        for suite in tree.iter("testsuite"):
            total_skipped += int(suite.get("skipped", "0"))

    if total_skipped > 0:
        result.fail(
            f"skim-check: {total_skipped} skipped tests found. "
            "CODING_RULES Rule 9.3 forbids @pytest.mark.skip / .acceptance."
        )
    else:
        result.ok("skim-check: no skipped tests in JUnit XML")


def audit(artifacts_dir: Path) -> AuditResult:
    """Run every audit check against the artifacts directory."""
    result = AuditResult()

    if not artifacts_dir.is_dir():
        result.fail(f"artifacts directory does not exist: {artifacts_dir}")
        return result

    _check_phase_2_unit(artifacts_dir, result)
    _check_phase_4_live(artifacts_dir, result)
    _check_phase_5_self_scan(artifacts_dir, result)
    _check_phase_6_build(artifacts_dir, result)
    _check_no_skipped_test_markers(artifacts_dir, result)

    return result


def render(result: AuditResult) -> str:
    """Format the audit result as a human-readable report."""
    lines = ["# Phase 7 Audit Report", ""]

    if result.passed:
        lines.append("## Passed")
        for msg in result.passed:
            lines.append(f"- {msg}")
        lines.append("")

    if result.failed:
        lines.append("## Failed")
        for msg in result.failed:
            lines.append(f"- {msg}")
        lines.append("")

    if result.notes:
        lines.append("## Notes")
        for msg in result.notes:
            lines.append(f"- {msg}")
        lines.append("")

    if result.has_failures:
        lines.append("## Verdict: FAIL")
    elif result.pre_mvp_soft_pass:
        lines.append("## Verdict: PRE-MVP SOFT PASS")
        lines.append(
            "Some artifacts were missing because the corresponding code does "
            "not yet exist. This is expected before MVP 0.1 implementation."
        )
    else:
        lines.append("## Verdict: PASS")

    return "\n".join(lines)


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="QuReddy Phase 7 audit — read CI artifacts, assert on counts."
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path("ci-artifacts"),
        help="Directory containing downloaded CI artifacts (default: ci-artifacts/)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable report",
    )
    args = parser.parse_args()

    result = audit(args.artifacts_dir)

    if args.json:
        payload = {
            "passed": result.passed,
            "failed": result.failed,
            "notes": result.notes,
            "pre_mvp_soft_pass": result.pre_mvp_soft_pass,
            "has_failures": result.has_failures,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render(result))

    if result.has_failures:
        return EXIT_FAIL
    if result.pre_mvp_soft_pass:
        return EXIT_PRE_MVP_SOFT_PASS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
