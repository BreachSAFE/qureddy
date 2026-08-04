# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Import-compatibility contract for the `qureddy.cli` package (ADR 0005).

The cli.py -> cli/ package split must preserve every externally-relied-on
import path: the pyproject entry point (`qureddy.cli:main`), `from
qureddy.cli import app`, and the legacy module-level names tests and
tooling already reach for. If one of these fails, the split broke a
public contract (ADR 0005 "No public API change").
"""

from __future__ import annotations

import importlib
import importlib.metadata

import typer

import qureddy._branding as branding_module
import qureddy.core.retry as retry_module
from qureddy.cli import MAX_RETRIES, MAX_RETRY_DELAY_SECONDS, app, main


def test_app_and_main_resolve_from_qureddy_cli() -> None:
    assert isinstance(app, typer.Typer)
    assert callable(main)


def test_entry_point_target_resolves() -> None:
    """pyproject's `qureddy = "qureddy.cli:main"` must keep resolving."""
    entry_points = importlib.metadata.entry_points(group="console_scripts", name="qureddy")
    (entry_point,) = entry_points
    assert entry_point.value == "qureddy.cli:main"
    assert entry_point.load() is main


def test_every_declared_public_symbol_resolves() -> None:
    cli_package = importlib.import_module("qureddy.cli")
    for symbol in cli_package.__all__:
        assert getattr(cli_package, symbol) is not None, f"__all__ names missing symbol {symbol}"


def test_legacy_identity_re_exports_point_at_canonical_homes() -> None:
    """Re-exports are the same objects, not copies (no drift possible)."""
    cli_package = importlib.import_module("qureddy.cli")
    assert cli_package.PROJECT_NAME is branding_module.PROJECT_NAME
    assert cli_package.VERSION_BANNER is branding_module.VERSION_BANNER
    assert MAX_RETRIES is retry_module.MAX_RETRIES
    assert MAX_RETRY_DELAY_SECONDS is retry_module.MAX_RETRY_DELAY_SECONDS


def test_subcommands_registered_in_pre_split_order() -> None:
    """Importing the package registers `scan tls` before `scan ssh`."""
    scan_main = importlib.import_module("qureddy.cli.main")
    registered = [command.name for command in scan_main.scan_app.registered_commands]
    assert registered == ["tls", "ssh"]
