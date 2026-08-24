# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-neutral collector implementations."""

from __future__ import annotations

from qureddy.collectors.native import NativeSSHCollector, NativeTLSCollector

__all__ = ["NativeSSHCollector", "NativeTLSCollector"]
