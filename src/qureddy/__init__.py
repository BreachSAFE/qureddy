# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""BreachSAFE QuReddy — post-quantum cryptography readiness scanner."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: the version declared in pyproject.toml, read
    # from installed package metadata. No hardcoded version string anywhere
    # in code — bump pyproject.toml and the banner, header, and
    # scanner_version all follow.
    __version__ = version("breachsafe-qureddy")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+source"
