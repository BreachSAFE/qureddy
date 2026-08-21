# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""String constants for `ScanMetadata.status`.

The `status` field on `ScanMetadata` is `str` (not an enum) per the
locked Pydantic model surface. These constants are the canonical values
producers should use, and consumers should compare against. Free-form
strings are forbidden in scanner code; ruff `PLR2004` (magic-value
detection) catches regressions.
"""

from __future__ import annotations

from typing import Final

#: Scan completed successfully without a top-level failure category.
STATUS_COMPLETED: Final = "completed"
