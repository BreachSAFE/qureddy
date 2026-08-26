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
        }
    ]
