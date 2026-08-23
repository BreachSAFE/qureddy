# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-agnostic scanner core shared by every scanner (TLS, SSH, and future).

One source of truth for the logic each scanner used to fork or drop: readiness/
severity rollup, error->FailureCategory mapping, retry, and algorithm classification
(#248). Nothing here is protocol-specific; a scanner supplies its own probe + findings
and folds them through these helpers so the verdict logic can't drift per protocol.
"""

from __future__ import annotations
