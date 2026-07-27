# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Local OpenSSL path, version, and TLS-group capability detection."""

from __future__ import annotations

import os
import re
import shutil
import subprocess

from packaging.version import InvalidVersion, Version

from qureddy.core.errors import (
    LocalOpenSSLBroken,
    LocalOpenSSLIsLibreSSL,
    LocalOpenSSLLacksGroup,
    LocalOpenSSLMissing,
    LocalOpenSSLTooOld,
    LocalOpenSSLVersionUnreadable,
)
from qureddy.core.models import FailureCategory, OpenSSLDependency

DEFAULT_TIMEOUT_SECONDS = 30
MIN_OPENSSL_VERSION = Version("3.5.0")
HYBRID_GROUP = "X25519MLKEM768"
CLASSICAL_GROUP = "X25519"
ENV_OVERRIDE = "QUREDDY_OPENSSL"

_OPENSSL_VERSION_PATTERN = re.compile(r"OpenSSL\s+(?P<version>\d+\.\d+\.\d+)")
_LIBRESSL_VERSION_PATTERN = re.compile(r"LibreSSL\s+(?P<version>\S+)")


def resolve_openssl_path(explicit: str | None) -> str:
    """Resolve ``--openssl``, then the environment override, then PATH."""
    candidate = explicit or os.environ.get(ENV_OVERRIDE) or shutil.which("openssl")
    if not candidate:
        raise LocalOpenSSLMissing(
            "openssl binary not found on PATH or via QUREDDY_OPENSSL",
            dependency=OpenSSLDependency(
                path=None,
                failure_category=FailureCategory.LOCAL_OPENSSL_MISSING,
            ),
        )
    if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
        raise LocalOpenSSLMissing(
            f"openssl path is not an executable file: {candidate}",
            dependency=OpenSSLDependency(
                path=candidate,
                failure_category=FailureCategory.LOCAL_OPENSSL_MISSING,
            ),
        )
    return candidate


def probe_capability(
    openssl_path: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> OpenSSLDependency:
    """Return typed version and group support for a local OpenSSL binary."""
    version_text = _run_openssl([openssl_path, "version"], timeout_seconds=timeout_seconds)
    groups_text = _run_openssl(
        [openssl_path, "list", "-tls1_3", "-tls-groups"],
        timeout_seconds=timeout_seconds,
    )
    groups = _parse_group_list(groups_text)
    return _dependency_from_capability(
        openssl_path,
        version_text,
        supports_groups=bool(groups),
        supports_hybrid=HYBRID_GROUP.lower() in {group.lower() for group in groups},
    )


def _dependency_from_capability(
    openssl_path: str,
    version_text: str,
    *,
    supports_groups: bool,
    supports_hybrid: bool,
) -> OpenSSLDependency:
    """Classify already-collected capability bytes without more subprocesses."""
    version = _extract_version(version_text)
    libressl_version = _extract_libressl_version(version_text)
    failure_category: FailureCategory | None = None
    rendered_version = str(version) if version is not None else libressl_version
    if libressl_version is not None:
        failure_category = FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL
    elif version is None:
        failure_category = FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE
    elif version < MIN_OPENSSL_VERSION:
        failure_category = FailureCategory.LOCAL_OPENSSL_TOO_OLD
    elif not supports_hybrid:
        failure_category = FailureCategory.LOCAL_OPENSSL_LACKS_GROUP
    return OpenSSLDependency(
        path=openssl_path,
        version=rendered_version,
        supports_tls13_groups=supports_groups,
        supports_x25519mlkem768=supports_hybrid,
        failure_category=failure_category,
    )


def raise_if_unusable(dep: OpenSSLDependency) -> None:
    """Translate an unusable dependency into its public typed exception."""
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_BROKEN:
        raise LocalOpenSSLBroken(
            f"OpenSSL at {dep.path} exited nonzero during capability detection",
            dependency=dep,
        )
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE:
        raise LocalOpenSSLVersionUnreadable(
            f"OpenSSL at {dep.path} produced unparseable version output "
            f"(required: {MIN_OPENSSL_VERSION})",
            dependency=dep,
        )
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL:
        raise LocalOpenSSLIsLibreSSL(_libressl_guidance(dep), dependency=dep)
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_TOO_OLD:
        raise LocalOpenSSLTooOld(
            f"OpenSSL {dep.version} is below required {MIN_OPENSSL_VERSION}",
            dependency=dep,
        )
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_LACKS_GROUP:
        raise LocalOpenSSLLacksGroup(
            f"OpenSSL at {dep.path} does not list {HYBRID_GROUP}",
            dependency=dep,
        )


def _libressl_guidance(dep: OpenSSLDependency) -> str:
    return (
        f"{dep.path} is LibreSSL {dep.version}, not OpenSSL — LibreSSL does not "
        f"support the PQC groups this scanner requires (OpenSSL {MIN_OPENSSL_VERSION}+, "
        f"needed for {HYBRID_GROUP}). On macOS, install real OpenSSL and point at it "
        f"explicitly: brew install openssl@3 && qureddy scan tls <target> --openssl "
        f"$(brew --prefix openssl@3)/bin/openssl — or export "
        f"{ENV_OVERRIDE}=$(brew --prefix openssl@3)/bin/openssl once instead of "
        f"passing --openssl every time."
    )


def _run_openssl(args: list[str], *, timeout_seconds: int) -> str:
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
    except subprocess.TimeoutExpired as exc:
        msg = (
            f"openssl did not respond within {timeout_seconds}s during capability "
            f"check ({args}); the binary exists but appears unresponsive — check "
            f"for entropy exhaustion or a hung process, or increase --timeout"
        )
        raise LocalOpenSSLBroken(
            msg,
            dependency=OpenSSLDependency(
                path=args[0],
                failure_category=FailureCategory.LOCAL_OPENSSL_BROKEN,
            ),
        ) from exc
    if completed.returncode != 0:
        snippet = (completed.stderr.strip() or "(no stderr)")[:200]
        raise LocalOpenSSLBroken(
            f"openssl exited with code {completed.returncode}: {snippet}",
            dependency=OpenSSLDependency(
                path=args[0],
                failure_category=FailureCategory.LOCAL_OPENSSL_BROKEN,
            ),
        )
    return completed.stdout


def _extract_version(text: str) -> Version | None:
    match = _OPENSSL_VERSION_PATTERN.search(text)
    if not match:
        return None
    try:
        return Version(match.group("version"))
    except InvalidVersion:
        return None


def _extract_libressl_version(text: str) -> str | None:
    match = _LIBRESSL_VERSION_PATTERN.search(text)
    return match.group("version") if match else None


def _parse_group_list(text: str) -> list[str]:
    tokens = re.split(r"[\s:]+", text.strip())
    return [token for token in tokens if token and not token.endswith(":") and ":" not in token]
