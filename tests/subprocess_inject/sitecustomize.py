# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Subprocess-only fault injection for installed-entrypoint contract tests."""

from __future__ import annotations

import os

if os.environ.get("QUREDDY_TEST_FORCE_TYPED_ERROR") == "1":
    from qureddy.core.errors import QureddyError
    from qureddy.scanners.tls.scanner import TLSScanner

    def _raise_typed_error(*_args: object, **_kwargs: object) -> None:
        raise QureddyError("forced typed scan failure")

    TLSScanner.scan = _raise_typed_error  # type: ignore[method-assign]
