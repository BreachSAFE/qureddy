# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rich console output adapter for `qureddy scan`.

Split from a single console.py into a purpose-organized package per ADR
0005 (file was over the 400-line hard ceiling, coding-rules.md Rule 2.2):

- `render`   — top-level orchestration + header
- `_verdict` — the verdict panel (headline + recommendation)
- `_tables`  — scan-details / findings / run-details tables
- `_errors`  — the Errors section
- `_commands`— the `-vvv` Commands panel
- `_evidence`— shared evidence selectors + cell styling

Color discipline (full rationale in `_styles.py`):

- PQ-positive signals → green
- Routine quantum_vulnerable findings → yellow (NOT red — every scan
  produces one from the classical control probe; red would teach
  operators to ignore the alarm)
- classically_weak / critical / high → red
- Unknowns → dim

NO_COLOR support follows https://no-color.org. No emoji or icons.
"""

from __future__ import annotations

from qureddy._branding import HEADER
from qureddy.output._styles import style_group, style_readiness, style_severity
from qureddy.output.console.render import render_rich

# Tests import these underscore-prefixed names from the renderer module
# (legacy convention). Re-exported here so `from qureddy.output.console
# import _style_group` keeps resolving across the package split. The
# canonical implementations live in `qureddy.output._styles`.
_style_group = style_group
_style_readiness = style_readiness
_style_severity = style_severity

__all__ = ["HEADER", "render_rich"]
