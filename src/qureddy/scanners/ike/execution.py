# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Backward-compatible import location for the shared process boundary.

The implementation moved to ``scanners.common.process`` when the artifact
scanner needed the same bounded subprocess contract.  Keep this module as a
small compatibility shim for existing integrations and tests; there is one
implementation and therefore one timeout/output-limit policy.
"""

from __future__ import annotations

from qureddy.scanners.common.process import (  # noqa: F401
    ProcessOutput,
    _BoundedCapture,
    _collect_process_output,
    _drain_pipe,
    _kill_process_tree,
    _start_readers,
    _terminate,
    run_bounded,
)

__all__ = ["ProcessOutput", "run_bounded"]
