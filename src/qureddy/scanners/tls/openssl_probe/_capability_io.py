# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Raw subprocess and parsing helpers for capability detection."""

from __future__ import annotations

import re
import subprocess

from packaging.version import InvalidVersion, Version

from qureddy.core.errors import LocalOpenSSLBroken, LocalOpenSSLMissing
from qureddy.core.models import FailureCategory, OpenSSLDependency

_OPENSSL_VERSION_PATTERN = re.compile(r"OpenSSL\s+(?P<version>\d+\.\d+\.\d+)")
_LIBRESSL_VERSION_PATTERN = re.compile(r"LibreSSL\s+(?P<version>\S+)")


def run_openssl(args: list[str], *, timeout_seconds: int) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 -- validated list-form command
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise LocalOpenSSLMissing(str(exc)) from exc
    except OSError as exc:
        # Windows reports a non-launchable file (for example WinError 193)
        # as OSError even when the path exists. Keep that local prerequisite
        # failure on the typed exit-3 surface instead of leaking a traceback.
        raise LocalOpenSSLBroken(
            f"openssl could not be launched: {exc}",
            dependency=_broken_dependency(args[0]),
        ) from exc
    except subprocess.TimeoutExpired as exc:
        message = (
            f"openssl did not respond within {timeout_seconds}s during capability "
            f"check ({args}); the binary exists but appears unresponsive — check "
            f"for entropy exhaustion or a hung process, or increase --timeout"
        )
        raise LocalOpenSSLBroken(
            message,
            dependency=_broken_dependency(args[0]),
        ) from exc
    if completed.returncode != 0:
        snippet = (completed.stderr.strip() or "(no stderr)")[:200]
        raise LocalOpenSSLBroken(
            f"openssl exited with code {completed.returncode}: {snippet}",
            dependency=_broken_dependency(args[0]),
        )
    return completed.stdout


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


def extract_libressl_version(text: str) -> str | None:
    match = _LIBRESSL_VERSION_PATTERN.search(text)
    return match.group("version") if match else None


def parse_group_list(text: str) -> list[str]:
    tokens = re.split(r"[\s:]+", text.strip())
    return [token for token in tokens if token and not token.endswith(":") and ":" not in token]
