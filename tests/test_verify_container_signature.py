# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Behavior tests for bounded container-signature propagation retries."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "verify_container_signature.sh"
IMAGE_REF = "docker.io/breachsafe/qureddy@sha256:abc123"


def _fake_tooling(tmp_path: Path, failures: int) -> tuple[dict[str, str], Path, Path]:
    state = tmp_path / "attempts"
    arguments = tmp_path / "arguments"
    sleeps = tmp_path / "sleeps"
    cosign = tmp_path / "cosign"
    sleep = tmp_path / "sleep"
    cosign.write_text(
        """#!/usr/bin/env bash
count=0
if [ -f "$FAKE_STATE" ]; then count="$(cat "$FAKE_STATE")"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_STATE"
printf '%s\n' "$*" >> "$FAKE_ARGUMENTS"
test "$count" -gt "$FAKE_FAILURES"
"""
    )
    sleep.write_text(
        """#!/usr/bin/env bash
printf '%s\n' "$1" >> "$FAKE_SLEEPS"
"""
    )
    cosign.chmod(0o755)
    sleep.chmod(0o755)
    environment = os.environ | {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "FAKE_STATE": str(state),
        "FAKE_ARGUMENTS": str(arguments),
        "FAKE_SLEEPS": str(sleeps),
        "FAKE_FAILURES": str(failures),
    }
    return environment, arguments, sleeps


def test_transient_registry_miss_retries_then_verifies(tmp_path: Path) -> None:
    environment, arguments, sleeps = _fake_tooling(tmp_path, failures=2)

    result = subprocess.run(  # noqa: S603 - fixed repository test helper.
        [str(SCRIPT), IMAGE_REF],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    calls = arguments.read_text().splitlines()
    assert len(calls) == 3
    assert all(call.startswith(f"verify {IMAGE_REF} ") for call in calls)
    assert all("--certificate-oidc-issuer" in call for call in calls)
    assert all("--certificate-identity-regexp" in call for call in calls)
    assert sleeps.read_text().splitlines() == ["2", "4"]


def test_persistent_verification_failure_exhausts_bound_and_fails(
    tmp_path: Path,
) -> None:
    environment, arguments, sleeps = _fake_tooling(tmp_path, failures=99)

    result = subprocess.run(  # noqa: S603 - fixed repository test helper.
        [str(SCRIPT), IMAGE_REF],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert len(arguments.read_text().splitlines()) == 5
    assert sleeps.read_text().splitlines() == ["2", "4", "6", "8"]
    assert "failed after 5 attempts" in result.stderr
