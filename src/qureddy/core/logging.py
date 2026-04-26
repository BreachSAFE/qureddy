# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Structured logging setup."""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import structlog


def configure_logging(*, verbosity: int = 0, json_logs: bool = False, quiet: bool = False) -> None:
    """Configure structlog. Logs go to stderr; never to stdout.

    Args:
        verbosity: 0=WARNING, 1=INFO, 2/3=DEBUG.
        json_logs: When True, emit JSON-formatted logs.
        quiet: When True, raise the level to ERROR.
    """
    level = _level_for(verbosity, quiet=quiet)
    logging.basicConfig(stream=sys.stderr, level=level, format="%(message)s", force=True)
    logging.getLogger().setLevel(level)
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]
    if json_logs:
        processors.append(structlog.processors.JSONRenderer())
    else:
        # Match the Rich console adapter: color when stderr is a real
        # terminal AND NO_COLOR is unset. The previous revision hardcoded
        # `colors=False`, which suppressed structlog's color output even
        # on real TTYs and was inconsistent with the Rich adapter's
        # NO_COLOR handling. Reviewer-flagged correctness fix.
        honor_color = sys.stderr.isatty() and "NO_COLOR" not in os.environ
        processors.append(structlog.dev.ConsoleRenderer(colors=honor_color))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a logger bound to `name` (typically ``__name__``)."""
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger


def _level_for(verbosity: int, *, quiet: bool) -> int:
    if quiet:
        return logging.ERROR
    if verbosity <= 0:
        return logging.WARNING
    if verbosity == 1:
        return logging.INFO
    return logging.DEBUG
