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
    2 = artifacts missing or malformed (reserved)

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

MIN_COVERAGE_PERCENT = 80.0
MIN_UNIT_TEST_COUNT_AT_MVP = 20
EXPECTED_PLATFORMS = ("ubuntu-latest", "macos-latest", "windows-latest")
EXPECTED_LIVE_TESTS = frozenset(
    {
        "test_pq_cloudflareresearch_hybrid",
        "test_example_com_classical_control_fires",
        "test_one_one_one_one_with_sni",
        "test_tls12_only_handshake_failure",
        "test_www_cloudflare_completes_within_timeout",
        "test_www_google_completes_within_timeout",
    }
)
EXPECTED_LIVE_TARGETS = (
    "www.cloudflare.com",
    "pq.cloudflareresearch.com",
    "www.google.com",
    "example.com",
    "1.1.1.1",
    "tls-v1-2.badssl.com",
)
EXPECTED_SELF_SCAN_STATUSES = {
    "cloudflare.json": "completed",
    "pq-cloudflare.json": "completed",
    "google.json": "completed",
    "example.json": "completed",
    "1111.json": "completed",
    "tls12.json": "tls_handshake_failed",
}


@dataclass
class AuditResult:
    """Aggregate audit verdict."""

    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def ok(self, msg: str) -> None:
        """Record a passing audit check."""
        self.passed.append(msg)

    def fail(self, msg: str) -> None:
        """Record a failing audit check."""
        self.failed.append(msg)

    def note(self, msg: str) -> None:
        """Record an informational audit note (neither pass nor fail)."""
        self.notes.append(msg)

    @property
    def has_failures(self) -> bool:
        """True iff at least one audit check failed."""
        return len(self.failed) > 0


def _check_phase_2_unit(artifacts: Path, result: AuditResult) -> None:
    """Verify unit tests ran and coverage >= 80%."""
    coverage_files = list(artifacts.glob("coverage-*/coverage.xml"))
    if not coverage_files:
        result.fail("phase-2: no coverage.xml artifacts found")
        return

    found_platforms = {path.parent.name.removeprefix("coverage-") for path in coverage_files}
    missing_platforms = sorted(set(EXPECTED_PLATFORMS) - found_platforms)
    if missing_platforms:
        result.fail(f"phase-2: missing coverage artifacts for: {', '.join(missing_platforms)}")

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

        junit_file = cov_file.parent / "pytest-results.xml"
        if not junit_file.is_file():
            result.fail(f"phase-2: missing pytest-results.xml at {cov_file.parent.name}")
            continue
        try:
            count = _count_tests_in_junit(junit_file)
        except ValueError as exc:
            result.fail(f"phase-2: {exc}")
            continue
        if count < MIN_UNIT_TEST_COUNT_AT_MVP:
            result.fail(
                f"phase-2: only {count} tests recorded at {cov_file.parent.name}; "
                f"required at least {MIN_UNIT_TEST_COUNT_AT_MVP}"
            )
        else:
            result.ok(f"phase-2: {count} unit tests recorded at {cov_file.parent.name}")


def _count_tests_in_junit(junit_path: Path) -> int:
    """Read a validated JUnit XML file and return its test count."""
    count, _failures, _errors, _skipped, _names = _read_junit(junit_path)
    return count


def _read_junit(junit_path: Path) -> tuple[int, int, int, int, set[str]]:
    """Return counts and exact testcase names from validated JUnit XML."""
    try:
        tree = ET.parse(junit_path)
    except ET.ParseError as exc:
        msg = f"malformed JUnit XML at {junit_path}: {exc}"
        raise ValueError(msg) from exc

    root_elem = tree.getroot()
    suites = root_elem.findall(".//testsuite") or [root_elem]
    names = {case.get("name", "") for case in root_elem.iter("testcase")}
    return (
        sum(int(s.get("tests", "0")) for s in suites),
        sum(int(s.get("failures", "0")) for s in suites),
        sum(int(s.get("errors", "0")) for s in suites),
        sum(int(s.get("skipped", "0")) for s in suites),
        names,
    )


def _check_phase_4_live(artifacts: Path, result: AuditResult) -> None:
    """Verify live tests covered every canonical target."""
    live_dirs = list(artifacts.glob("live-results-*"))
    if not live_dirs:
        result.fail("phase-4: no live-results-* artifacts found")
        return

    found_platforms = {path.name.removeprefix("live-results-") for path in live_dirs}
    missing_platforms = sorted(set(EXPECTED_PLATFORMS) - found_platforms)
    if missing_platforms:
        result.fail(f"phase-4: missing live artifacts for: {', '.join(missing_platforms)}")

    for live_dir in live_dirs:
        junit_file = live_dir / "live-results.xml"
        if not junit_file.is_file():
            result.fail(f"phase-4: missing live-results.xml at {live_dir.name}")
            continue
        try:
            count, failures, errors, skipped, names = _read_junit(junit_file)
        except ValueError as exc:
            result.fail(f"phase-4: {exc}")
            continue
        missing_tests = sorted(EXPECTED_LIVE_TESTS - names)
        unexpected_tests = sorted(names - EXPECTED_LIVE_TESTS)
        if count != len(EXPECTED_LIVE_TESTS) or missing_tests or unexpected_tests:
            result.fail(
                f"phase-4: testcase mismatch at {live_dir.name}: count={count}, "
                f"missing={missing_tests}, unexpected={unexpected_tests}"
            )
        elif failures or errors or skipped:
            result.fail(
                f"phase-4: non-passing live cases at {live_dir.name}: "
                f"failures={failures}, errors={errors}, skipped={skipped}"
            )
        else:
            result.ok(f"phase-4: all {count} exact live testcases passed at {live_dir.name}")


def _check_phase_5_self_scan(artifacts: Path, result: AuditResult) -> None:
    """Verify self-scan ran for every canonical target."""
    self_scan_dir = artifacts / "phase-5-self-scan"
    if not self_scan_dir.is_dir():
        result.fail("phase-5: no phase-5-self-scan artifact directory")
        return

    json_files = sorted(self_scan_dir.glob("*.json"))
    if not json_files:
        result.fail("phase-5: scanner directory present but no JSON outputs")
        return

    found_names = {path.name for path in json_files}
    expected_names = set(EXPECTED_SELF_SCAN_STATUSES)
    missing_files = sorted(expected_names - found_names)
    unexpected_files = sorted(found_names - expected_names)
    if missing_files or unexpected_files:
        result.fail(
            f"phase-5: self-scan file mismatch: missing={missing_files}, "
            f"unexpected={unexpected_files}"
        )

    found_targets: set[str] = set()
    for json_file in json_files:
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            result.fail(f"phase-5: malformed JSON at {json_file.name}: {e}")
            continue

        target = data.get("target", {}).get("host", "<unknown>")
        found_targets.add(target)

        scan_meta = data.get("scan", {})
        status = scan_meta.get("status", "<missing>")
        expected_status = EXPECTED_SELF_SCAN_STATUSES.get(json_file.name)
        if expected_status is not None and status != expected_status:
            result.fail(
                f"phase-5: {json_file.name} has scan.status={status}; expected {expected_status}"
            )

    missing_targets = sorted(set(EXPECTED_LIVE_TARGETS) - found_targets)
    unexpected_targets = sorted(found_targets - set(EXPECTED_LIVE_TARGETS))
    if missing_targets or unexpected_targets:
        result.fail(
            f"phase-5: self-scan target mismatch: missing={missing_targets}, "
            f"unexpected={unexpected_targets}"
        )
    elif not missing_files and not unexpected_files:
        result.ok(
            f"phase-5: self-scan covered {len(found_targets)} exact canonical targets "
            "with expected statuses"
        )


def _check_phase_6_build(artifacts: Path, result: AuditResult) -> None:
    """Verify the build produced both sdist and wheel."""
    dist_dir = artifacts / "phase-6-dist"
    if not dist_dir.is_dir():
        result.fail("phase-6: no phase-6-dist artifact directory")
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
    junit_files = (
        list(artifacts.rglob("*junit*.xml"))
        + list(artifacts.rglob("pytest-results*.xml"))
        + list(artifacts.rglob("live-results*.xml"))
    )
    if not junit_files:
        result.fail("skim-check: no JUnit XML found")
        return

    total_skipped = 0
    for junit_file in junit_files:
        try:
            tree = ET.parse(junit_file)
        except ET.ParseError as exc:
            result.fail(f"skim-check: malformed JUnit XML at {junit_file}: {exc}")
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
            "has_failures": result.has_failures,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render(result))

    if result.has_failures:
        return EXIT_FAIL
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
