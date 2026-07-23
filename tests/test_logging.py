# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the structured logging configuration."""

from __future__ import annotations

import io
import json
import logging
import sys

import pytest
import structlog
import structlog.dev

from qureddy.core.logging import configure_logging, get_logger


def test_default_verbosity_is_warning() -> None:
    configure_logging(verbosity=0)
    log = logging.getLogger()
    assert log.level == logging.WARNING


def test_minus_v_yields_info() -> None:
    configure_logging(verbosity=1)
    log = logging.getLogger()
    assert log.level == logging.INFO


def test_minus_vv_yields_debug() -> None:
    configure_logging(verbosity=2)
    log = logging.getLogger()
    assert log.level == logging.DEBUG


def test_quiet_overrides_verbosity() -> None:
    configure_logging(verbosity=2, quiet=True)
    log = logging.getLogger()
    assert log.level == logging.ERROR


def test_json_logs_emit_valid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", fake_stderr)
    configure_logging(verbosity=1, json_logs=True, log_stream=fake_stderr)
    log = get_logger("test")
    log.info("scan.start", target="tls://example.com:443")
    output = fake_stderr.getvalue().strip()
    assert output, "expected at least one log line"
    payload = json.loads(output.splitlines()[0])
    assert payload["event"] == "scan.start"
    assert payload["target"] == "tls://example.com:443"


def test_context_vars_propagate_to_nested_loggers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`scan_id` and `target` bound at the scan boundary must appear on
    every log call, including ones emitted from nested modules.

    The MVP requires correlation tags survive across module boundaries
    so a log file can be filtered to a single scan run.
    """
    fake_stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", fake_stderr)
    configure_logging(verbosity=1, json_logs=True, log_stream=fake_stderr)

    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        scan_id="scan-deadbeef",
        target="tls://example.com:443",
    )
    try:
        log_outer = get_logger("qureddy.cli")
        log_outer.info("scan.start", host="example.com")
        log_nested = get_logger("qureddy.scanners.tls.scanner")
        log_nested.info("probe.start", group="X25519MLKEM768")
    finally:
        structlog.contextvars.clear_contextvars()

    lines = [json.loads(line) for line in fake_stderr.getvalue().splitlines() if line.strip()]
    assert len(lines) >= 2, "expected at least two log lines"
    for entry in lines:
        assert entry["scan_id"] == "scan-deadbeef"
        assert entry["target"] == "tls://example.com:443"

    events = {entry["event"] for entry in lines}
    assert "scan.start" in events
    assert "probe.start" in events


def test_logger_binds_to_kernel_stderr_not_sys_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default logging must ignore later Python-level stderr rebinding."""
    fake_stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", fake_stderr)
    configure_logging(verbosity=1, json_logs=True)

    log = get_logger("test")
    log.info("scan.start", target="tls://example.com:443")

    assert fake_stderr.getvalue() == ""


class _FakeStream(io.StringIO):
    """A StringIO with a settable `isatty()` — the actual destination
    stream a caller controls via `log_stream`, independent of whatever
    the real process's `sys.stderr` happens to be."""

    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def test_console_renderer_color_honors_tty_and_no_color(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ConsoleRenderer color is on iff the destination stream is a TTY and NO_COLOR is unset.

    Reviewer-flagged regression: a previous revision hardcoded
    `colors=False`, suppressing color even on real terminals.

    Issue #231: the color decision must read the actual destination
    `stream` (`log_stream` when the caller passes one), not `sys.stderr`
    — those can diverge. This test passes a controllable `log_stream`
    rather than monkeypatching `sys.stderr`, which is exactly the
    divergence #231 is about: monkeypatching `sys.stderr.isatty` must
    have *no* effect on the color decision once a `log_stream` is given.
    """

    def _renderer_color_flag(*, stream_is_tty: bool) -> bool:
        configure_logging(verbosity=1, json_logs=False, log_stream=_FakeStream(tty=stream_is_tty))
        # The last processor is the ConsoleRenderer (we passed
        # json_logs=False). `_colors` mirrors the constructor arg.
        config = structlog.get_config()
        renderer = config["processors"][-1]
        assert isinstance(renderer, structlog.dev.ConsoleRenderer)
        return renderer._colors  # noqa: SLF001 -- intentional probe

    # sys.stderr.isatty is deliberately mocked to the *opposite* of the
    # log_stream's tty-ness in every case below, proving the decision
    # tracks log_stream, not sys.stderr.

    # NO_COLOR set → color disabled regardless of TTY.
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert _renderer_color_flag(stream_is_tty=True) is False, "NO_COLOR=1 should disable color"

    # Non-TTY destination stream → color disabled regardless of NO_COLOR
    # or what sys.stderr.isatty() claims.
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert _renderer_color_flag(stream_is_tty=False) is False, "non-TTY stream should disable color"

    # TTY destination stream + no NO_COLOR → color enabled, even though
    # sys.stderr.isatty() claims False.
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    assert _renderer_color_flag(stream_is_tty=True) is True, (
        "TTY stream without NO_COLOR should enable color"
    )
