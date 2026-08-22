# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Structured logging for OpenSSL subprocess boundaries."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.logging import get_logger

if TYPE_CHECKING:
    from qureddy.core.models import FailureCategory

_log = get_logger(__name__)


def log_subprocess_start(args: list[str], timeout_seconds: int, attempt_number: int) -> None:
    _log.debug(
        "subprocess.start",
        executable=args[0],
        args=tuple(args[1:]),
        timeout_seconds=timeout_seconds,
        attempt_number=attempt_number,
    )


def log_subprocess_complete(
    args: list[str],
    return_code: int,
    duration_ms: int,
    attempt_number: int,
    failure: FailureCategory | None,
) -> None:
    _log.debug(
        "subprocess.complete",
        executable=args[0],
        args=tuple(args[1:]),
        return_code=return_code,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        failure_category=failure.value if failure else None,
    )
