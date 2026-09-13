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


def test_the_responder_answers_and_the_scan_says_which_mode(scan: dict) -> None:
    """An answered mode is the evidence an absent lab cannot produce (#1019)."""
    modes = _modes(scan)

    assert "ike.mode.responded" in modes.values()
    assert modes["ikev2"] == "ike.mode.responded"


def test_a_rejected_proposal_is_recorded_as_a_reachable_responder(scan: dict) -> None:
    """A rejection proves reachability, which silence does not."""
    modes = _modes(scan)

    assert modes["ikev1_main"] == "ike.mode.rejected"
    assert modes["ikev1_aggressive"] == "ike.mode.rejected"
    assert "ike.proposal.rejected" in _rules(scan)


def test_the_key_exchange_is_graded(scan: dict) -> None:
    """The finding this lane exists to reach, and no hermetic test can."""
    assert "ike.kex.classical" in _rules(scan)
    assert "ike.responder.tool_reported" in _rules(scan)


def test_a_weak_diffie_hellman_group_is_reported(scan: dict) -> None:
    """Group 2 is 1024-bit MODP. The summary carries the severity it earns."""
    assert "ike.kex.weak" in _rules(scan)
    assert scan["summary"]["readiness"] == "classically_weak"
    assert scan["summary"]["highest_severity"] in {"medium", "high", "critical"}
