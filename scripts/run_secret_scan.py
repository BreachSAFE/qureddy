#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run the release gate's pinned, checksum-verified secret scanner."""

from __future__ import annotations

import subprocess

from release_support import ROOT, download_tool

TIMEOUT_SECONDS = 300


def main() -> int:
    """Scan the complete current Git history with the pinned Gitleaks binary."""
    cache = ROOT / ".cache" / "release-tools"
    cache.mkdir(parents=True, exist_ok=True)
    gitleaks = download_tool("gitleaks", cache)
    completed = subprocess.run(  # noqa: S603 - executable is checksum-verified before use
        [str(gitleaks), "git", "--no-banner", "--log-opts=HEAD", str(ROOT)],
        cwd=ROOT,
        check=False,
        timeout=TIMEOUT_SECONDS,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
