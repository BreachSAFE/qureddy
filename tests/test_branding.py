# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the canonical branding module.

The branding module is the single source of truth for project name,
URL, source URL, license, and the version banner. Both `qureddy.cli`
and `qureddy.output.console` import from it. Drift between consumers
would mean the help screen, the verdict panel, and the JSON output
disagree about what the product is called — exactly the bug class the
agent-antipatterns "Copy-paste duplication" rule is meant to prevent.
"""

from __future__ import annotations

import qureddy._branding as branding_module
import qureddy.cli as cli_module
import qureddy.output.console as console_module
from qureddy import __version__
from qureddy._branding import (
    HEADER,
    LICENSE_NAME,
    PROJECT_NAME,
    PROJECT_URL,
    SOURCE_URL,
    VERSION_BANNER,
)


def test_project_name_is_breachsafe_qureddy() -> None:
    assert PROJECT_NAME == "BreachSAFE QuReddy"


def test_project_url_is_breachsafe_dot_ai() -> None:
    assert PROJECT_URL == "https://www.breachsafe.ai"


def test_source_url_is_breachsafe_qureddy() -> None:
    """Maintainer-locked URL per #41 comment thread (not breachsafe/qureddy)."""
    assert SOURCE_URL == "https://github.com/breachsafe/qureddy"


def test_license_is_apache_2_0() -> None:
    assert LICENSE_NAME == "Apache-2.0"


def test_version_banner_uses_canonical_version() -> None:
    """Banner reads version from `qureddy.__version__`, not a hardcoded literal.

    Pin against the imported value so a 0.1.0 → 0.2.0 bump in
    `__init__.py` automatically propagates without breaking the format
    contract. The original `HEADER = "QuReddy 0.1.0 by BreachSAFE"`
    was a hardcoded-version drift bug; this test prevents its return.
    """
    assert __version__ in VERSION_BANNER
    assert PROJECT_NAME in VERSION_BANNER
    assert PROJECT_URL in VERSION_BANNER
    assert " -- " in VERSION_BANNER, "expected '--' separator (not em-dash)"


def test_console_header_uses_canonical_version() -> None:
    """The Rich-output HEADER also reads from `__version__`.

    Before this refactor, `output/console.py` defined
    `HEADER = "QuReddy 0.1.0 by BreachSAFE"` with the version
    hardcoded as a literal — drifts on every release. After: HEADER
    references `__version__` via the branding module so help, verdict,
    and JSON consumers all agree about which version they're seeing.
    """
    assert __version__ in HEADER
    assert "BreachSAFE" in HEADER
    assert "QuReddy" in HEADER


def test_cli_module_re_exports_canonical_branding() -> None:
    """`qureddy.cli` consumes branding via import, not by re-defining.

    Catches the regression shape where someone copies `PROJECT_NAME = ...`
    back into `cli.py` instead of importing from `_branding`. Identity
    check (`is`) — same object, not just equal value.

    Slice 1 of #41 imports `PROJECT_NAME` and `VERSION_BANNER` only.
    Slices 3-4 (epilogs) will add `PROJECT_URL`, `SOURCE_URL`, and
    `LICENSE_NAME` to cli.py's import list when those constants get
    consumed. Tests for those re-exports land with their slices.
    """
    assert cli_module.PROJECT_NAME is branding_module.PROJECT_NAME
    assert cli_module.VERSION_BANNER is branding_module.VERSION_BANNER


def test_console_module_re_exports_canonical_header() -> None:
    """`qureddy.output.console` consumes HEADER via import, not literal.

    Before refactor: `HEADER = "QuReddy 0.1.0 by BreachSAFE"` —
    a literal that drifts on every release. After: HEADER comes from
    the branding module.
    """
    assert console_module.HEADER is branding_module.HEADER
