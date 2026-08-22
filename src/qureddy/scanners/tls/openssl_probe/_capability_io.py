# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Raw subprocess and parsing helpers for capability detection."""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

from qureddy.core.errors import LocalOpenSSLBroken
from qureddy.core.models import FailureCategory, OpenSSLDependency
from qureddy.scanners.tls.openssl_probe.executor import raise_for_launch
from qureddy.scanners.tls.openssl_probe.executor import run_openssl as execute

_OPENSSL_RELEASE_FRAGMENT = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z._-]*)?"
_OPENSSL_VERSION_PATTERN = re.compile(
    rf"^\s*OpenSSL\s+(?P<version>{_OPENSSL_RELEASE_FRAGMENT})(?=\s|$)",
)
_OPENSSL_LIBRARY_VERSION_PATTERN = re.compile(
    rf"\(Library:\s*OpenSSL\s+(?P<version>{_OPENSSL_RELEASE_FRAGMENT})(?=\s|\))",
)
_LIBRESSL_VERSION_PATTERN = re.compile(r"LibreSSL\s+(?P<version>\S+)")


def run_openssl(args: list[str], *, timeout_seconds: int) -> str:
    """Return stdout from a capability-check invocation, or raise exit-3 typed.

    A missing or unlaunchable binary (Windows WinError 193 surfaces as OSError
    even when the path exists), an unresponsive hang, or any nonzero exit during
    capability detection is a local-prerequisite failure, kept on the typed
    exit-3 surface instead of leaking a traceback.
    """
    outcome = execute(args, timeout_seconds=timeout_seconds)
    raise_for_launch(outcome, args[0])
    if outcome.timed_out:
        message = (
            f"openssl did not respond within {timeout_seconds}s during capability "
            f"check ({args}); the binary exists but appears unresponsive — check "
            f"for entropy exhaustion or a hung process, or increase --timeout"
        )
        raise LocalOpenSSLBroken(message, dependency=_broken_dependency(args[0]))
    if outcome.returncode != 0:
        snippet = (outcome.stderr.strip() or "(no stderr)")[:200]
        raise LocalOpenSSLBroken(
            f"openssl exited with code {outcome.returncode}: {snippet}",
            dependency=_broken_dependency(args[0]),
        )
    return outcome.stdout


def _broken_dependency(path: str) -> OpenSSLDependency:
    return OpenSSLDependency(
        path=path,
        failure_category=FailureCategory.LOCAL_OPENSSL_BROKEN,
    )


def extract_version(text: str) -> Version | None:
    match = _OPENSSL_VERSION_PATTERN.search(text)
    if not match:
        return None
    try:
        return Version(match.group("version"))
    except InvalidVersion:
        return None


def extract_library_version(text: str) -> Version | None:
    """Return an explicitly reported linked-library version, when present."""
    match = _OPENSSL_LIBRARY_VERSION_PATTERN.search(text)
    if not match:
        return None
    try:
        return Version(match.group("version"))
    except InvalidVersion:
        return None


def extract_libressl_version(text: str) -> str | None:
    match = _LIBRESSL_VERSION_PATTERN.search(text)
    return match.group("version") if match else None


def parse_group_list(text: str) -> list[str]:
    tokens = re.split(r"[\s:]+", text.strip())
    return [token for token in tokens if token and not token.endswith(":") and ":" not in token]
