# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Structured logging setup."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, TextIO

import structlog


def _open_stderr_fd() -> TextIO:
    """Return a text stream bound to the original process stderr fd."""
    fd = os.dup(2)
    return os.fdopen(fd, "w", buffering=1)


_STDERR = _open_stderr_fd()


def _open_log_file(path: Path) -> TextIO:
    """Open a file to capture a run's logs, creating parent directories as needed.

    Returns a line-buffered text stream for ``configure_logging(log_stream=...)``. Backs the
    ``--log PATH`` option; logs are diagnostics and stay off stdout. The caller owns closing it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", buffering=1, encoding="utf-8")


def configure_logging(
    *,
    verbosity: int = 0,
    json_logs: bool = False,
    quiet: bool = False,
    log_stream: TextIO | None = None,
) -> None:
    """Configure structlog. Logs go to stderr; never to stdout.

    Args:
        verbosity: 0=WARNING, 1=INFO, 2/3=DEBUG.
        json_logs: When True, emit JSON-formatted logs.
        quiet: When True, raise the level to ERROR.
        log_stream: Optional stream for tests that need to inspect log output.
    """
    level = _level_for(verbosity, quiet=quiet)
    stream = _STDERR if log_stream is None else log_stream
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]
    if json_logs:
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        # Match the Rich console adapter: color when stderr is a real
        # terminal AND NO_COLOR is unset. The previous revision hardcoded
        # `colors=False`, which suppressed structlog's color output even
        # on real TTYs and was inconsistent with the Rich adapter's
        # NO_COLOR handling. Reviewer-flagged correctness fix.
        #
        # Issue #231: the color decision must be based on the actual
        # destination `stream` (which is `log_stream` when the caller
        # passes one), not `sys.stderr` — those diverge whenever
        # `log_stream` is set, and a non-tty log_stream (e.g. a test's
        # io.StringIO) got polluted with ANSI codes whenever the real
        # process stderr happened to be a terminal. `getattr` guards
        # test doubles that don't implement `isatty` at all.
        honor_color = getattr(stream, "isatty", bool)() and "NO_COLOR" not in os.environ
        renderer = structlog.dev.ConsoleRenderer(colors=honor_color)
    processors.append(renderer)

    # Third-party libraries use stdlib logging, so give those records the same
    # renderer rather than letting a raw message break the JSONL contract.
    foreign_formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=processors[:-1],
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )
    handler = logging.StreamHandler(stream)
    handler.setFormatter(foreign_formatter)
    logging.basicConfig(handlers=[handler], level=level, force=True)
    logging.getLogger().setLevel(level)

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=stream),
        cache_logger_on_first_use=True,
    )


def start_run_logging(
    *, verbosity: int, json_logs: bool, quiet: bool, log: Path | None
) -> TextIO | None:
    """Configure logging for one CLI run, capturing to a file when ``log`` is set.

    Returns the opened log-file stream (the caller closes it) or ``None`` when logging to
    stderr. Shared by the scan subcommands so the log-capture wiring lives in one place.
    """
    stream = _open_log_file(log) if log is not None else None
    # An explicit file is a diagnostic record, not the terminal. Preserve its INFO
    # contract even when ``-q`` was supplied; quiet remains meaningful for the default
    # stderr destination. Keeping this policy here makes all CLI callers consistent.
    file_logging = log is not None
    configure_logging(
        verbosity=max(verbosity, 1) if file_logging else verbosity,
        json_logs=json_logs,
        quiet=False if file_logging else quiet,
        log_stream=stream,
    )
    return stream


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
