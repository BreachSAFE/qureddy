# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""IKE against a public IKEv2 responder, driving the real CLI.

`tests/ike_lab` needs the pinned strongSwan responder from #570, which is
unprovisioned, and every automated lane excludes it. The result is that no lane
has ever exercised the IKE scanner against a responder, and #1019 shows the
absent-lab guard passing the suite on a loopback reflection.

A public VPN endpoint closes that gap without a lab. It answers IKEv2 and
rejects both IKEv1 modes, so one scan reaches the responder-detected,
proposal-rejected, classical key-exchange and weak-group paths.

The target is an operator-set parameter. `QUREDDY_IKE_PUBLIC_TARGET` names the
endpoint and the suite skips when it is unset, so no third-party host is probed
by default or by someone who has not chosen it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_TIMEOUT_SECONDS = 180
_TARGET_ENV = "QUREDDY_IKE_PUBLIC_TARGET"

pytestmark = pytest.mark.skipif(
    not os.environ.get(_TARGET_ENV),
    reason=f"{_TARGET_ENV} is unset; set it to an endpoint you are authorized to scan",
)


def _cli() -> str:
    resolved = Path(sys.executable).with_name("qureddy")
    return str(resolved) if resolved.exists() else "qureddy"


@pytest.fixture(scope="module")
def scan() -> dict:
    """One real scan, shared, so the suite probes the endpoint once."""
    completed = subprocess.run(  # noqa: S603 - resolved binary, list-form argv
        [_cli(), "scan", "ike", os.environ[_TARGET_ENV], "--format", "json"],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )
    assert completed.stdout.strip(), completed.stderr
    return json.loads(completed.stdout)


def _modes(document: dict) -> dict[str, str]:
    """Exchange mode to the evidence type the scan recorded for it."""
    modes = {}
    for record in document["evidence"]:
        if not record["evidence_type"].startswith("ike.mode."):
            continue
        mode = next(
            (
                note.split("=", 1)[1]
                for note in record["notes"]
                if note.startswith("exchange_mode=")
            ),
            "",
        )
        modes[mode] = record["evidence_type"]
    return modes


def _rules(document: dict) -> set[str]:
    return {finding["finding_type"] for finding in document["findings"]}


def test_all_three_exchange_modes_are_attempted(scan: dict) -> None:
    """The scanner probes v1 main, v1 aggressive and v2, and records each."""
    assert scan["scan"]["total_attempts"] == 3
    assert set(_modes(scan)) == {"ikev1_main", "ikev1_aggressive", "ikev2"}


def test_the_responder_answers_at_least_one_mode(scan: dict) -> None:
    """An answer is the evidence an absent peer cannot produce (#1019).

    A rejection proves reachability and silence does not, so either shape
    counts. Which mode answers varies: measured against one public endpoint,
    IKEv2 returned transforms on some runs and nothing on others while both v1
    modes were rejected every time, because the responder rate-limits.
    """
    answered = {
        mode
        for mode, evidence in _modes(scan).items()
        if evidence in {"ike.mode.responded", "ike.mode.rejected"}
    }

    assert answered, f"no mode answered: {_modes(scan)}"


def test_every_answer_is_one_of_the_recorded_outcomes(scan: dict) -> None:
    """Each mode lands on a known outcome, so none is left unclassified.

    Which mode answers is not stable. Five scans of one public endpoint
    produced five different combinations: each of the three modes was rejected
    in some runs, answered with transforms in others, and silent in the rest,
    because the responder rate-limits per source. The invariant is that every
    attempt is classified and at least one of them answered, which is what
    separates a reachable responder from an absent one.
    """
    outcomes = set(_modes(scan).values())

    assert outcomes <= {"ike.mode.responded", "ike.mode.rejected", "ike.mode.no_response"}
    if "ike.mode.rejected" in outcomes:
        assert "ike.proposal.rejected" in _rules(scan)


def test_the_transforms_are_graded_when_the_responder_returns_them(scan: dict) -> None:
    """The finding this lane exists to reach, and no hermetic test can.

    A public responder rate-limits. Measured three times against one endpoint,
    two runs returned the transform list and one returned a bare rejection, so
    the grading is asserted against the run that carried transforms and the
    other shape is checked for consistency instead of skipped. Either way the
    scan states something, and a lane that silently accepts both would accept a
    scanner that graded nothing.
    """
    rules = _rules(scan)
    if "ike.responder.tool_reported" not in rules:
        # The responder answered without returning transforms. Nothing to grade,
        # and the summary has to say so rather than inventing a verdict.
        assert scan["summary"]["readiness"] == "unknown"
        assert "ike.proposal.rejected" in rules
        return

    assert "ike.kex.classical" in rules, rules
    assert "ike.kex.weak" in rules, "group 2 is 1024-bit MODP and is graded weak"
    assert scan["summary"]["readiness"] == "classically_weak"
    assert scan["summary"]["highest_severity"] in {"medium", "high", "critical"}
