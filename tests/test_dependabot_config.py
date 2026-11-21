# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Repository automation contract tests."""

from __future__ import annotations

from pathlib import Path

import yaml


def test_dependabot_monitors_digest_pinned_docker_bases() -> None:
    """Docker base-image updates must receive automated weekly proposals."""
    config = yaml.safe_load((Path(__file__).parents[1] / ".github" / "dependabot.yml").read_text())
    docker_updates = [
        update for update in config["updates"] if update["package-ecosystem"] == "docker"
    ]
    assert docker_updates == [
        {
            "package-ecosystem": "docker",
            "directory": "/",
            "schedule": {
                "interval": "weekly",
                "day": "monday",
                "time": "06:00",
                "timezone": "Etc/UTC",
            },
            "open-pull-requests-limit": 5,
            "labels": ["dependencies", "docker"],
            "commit-message": {"prefix": "build", "include": "scope"},
            # Both OpenSSL stages share one repository path, so Dependabot cannot
            # tell the 3.5.8 current-strength lane from the 1.0.2u compatibility
            # lane. The version bound refuses anything past the platform pin and
            # leaves 3.5.x patch and digest proposals flowing.
            "ignore": [
                {
                    "dependency-name": "paul007ex/breachsafe-openssl",
                    "versions": [">= 3.6"],
                }
            ],
        }
    ]


def test_dependabot_refuses_openssl_updates_past_the_platform_pin() -> None:
    """The compatibility lane keeps its 1.0.2u OpenSSL.

    Both build stages resolve from ghcr.io/paul007ex/breachsafe-openssl, so a
    `dependency-name` ignore with no bound would also stop the wanted 3.5.8
    digest refresh. The bound is what separates them: 3.5.x proposals flow,
    anything at or past 3.6 is refused, and the 1.0.2u legacy stage is never a
    bump candidate. PR #1036 proposed 1.0.2u -> 4.0.2, which would have dropped
    the SSLv3 and weak suites that stage exists to offer.
    """
    config = yaml.safe_load((Path(__file__).parents[1] / ".github" / "dependabot.yml").read_text())
    docker = next(u for u in config["updates"] if u["package-ecosystem"] == "docker")
    rule = next(
        entry
        for entry in docker["ignore"]
        if entry["dependency-name"] == "paul007ex/breachsafe-openssl"
    )
    assert rule["versions"] == [">= 3.6"]
