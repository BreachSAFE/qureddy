# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Canonical branding constants for QuReddy.

Single source of truth for the project name, URL, source URL, license,
version banner, and Rich-output header. Both `qureddy.cli` and
`qureddy.output.console` import from here. Defining any of these
values twice (in cli.py + console.py, in cli.py + a test, etc.)
violates the "Copy-paste duplication" rule in
`docs/contributors/agent-antipatterns.md` because identity values
(name, URL, version) are exactly the values that drift silently and
make help / verdict / JSON output disagree about what the product is
called.

This module is intentionally implementation-internal (`_branding`,
underscore-prefixed) per the project's existing convention for shared
implementation modules (`output/_styles.py`,
`scanners/tls/_classify.py`). When `cli.py` is promoted to a `cli/`
package per issue #60, this module moves to `cli/_branding.py` and
the consumers' import paths shift via `cli/__init__.py` re-exports.

Notes on the format:

- `--` (double-hyphen) is used in `VERSION_BANNER` and visible help
  text instead of an em-dash per `docs/contributors/coding-rules.md`
  §18 (no em-dashes in source).
- `SOURCE_URL` points at `breachsafe/qureddy`, the canonical public
  repository (org cutover from the `breachsafe/qureddy` staging repo
  org-migration target is documented in the contributor materials while the
  canonical public repository remains `breachsafe/qureddy`.
"""

from __future__ import annotations

from qureddy import __version__ as _qureddy_version

PROJECT_NAME = "BreachSAFE QuReddy"
PUBLIC_DOMAIN = "breachsafe.io"
PROJECT_URL = f"https://www.{PUBLIC_DOMAIN}"
SOURCE_URL = "https://github.com/breachsafe/qureddy"
LICENSE_NAME = "Apache-2.0"
PROJECT_VERSION = _qureddy_version

# One-line description, used in CLI help (root + callback). Single source so
# the two help strings can't drift.
DESCRIPTION = "post-quantum readiness scanner for TLS, SSH, and IKE endpoints"

# Used by `qureddy --version` / `qureddy -V`. Single line, branded.
VERSION_BANNER = f"{PROJECT_NAME} {_qureddy_version} -- {PROJECT_URL}"

# Used at the top of the Rich console output (`qureddy scan tls TARGET`
# without --format json). Reads version from `__version__` so a release
# bump propagates without code changes — the original
# `HEADER = "QuReddy 0.1.0 by BreachSAFE"` was a hardcoded-version
# drift bug.
HEADER = f"QuReddy {_qureddy_version} by BreachSAFE · {PROJECT_URL}"
