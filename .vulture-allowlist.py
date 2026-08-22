# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""vulture allowlist (#360).

Names here are intentionally-unused-looking symbols that vulture flags as dead
code but are actually reachable (framework hooks, protocol members, re-exports).

Empty today: ``vulture src/qureddy --min-confidence 80`` is clean. As false
positives appear, add the symbol here (e.g. ``_.some_attribute``) rather than
lowering the confidence threshold.
"""
