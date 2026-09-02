# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Read process-environment policy at the CLI boundary."""

from __future__ import annotations

import os


def block_internal_targets() -> bool:
    """Return whether embedders opted into rejecting internal target addresses."""
    return os.environ.get("QUREDDY_BLOCK_INTERNAL_TARGETS", "").strip().lower() not in (
        "",
        "0",
        "false",
        "no",
    )
