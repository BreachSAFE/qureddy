# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Local OpenSSL path, version, and TLS-group capability detection."""

from __future__ import annotations

import os
import shutil

from qureddy.core.errors import (
    LocalOpenSSLBroken,
    LocalOpenSSLIsLibreSSL,
    LocalOpenSSLLacksGroup,
    LocalOpenSSLMissing,
    LocalOpenSSLTooOld,
    LocalOpenSSLVersionUnreadable,
)
from qureddy.core.models import FailureCategory, OpenSSLDependency
from qureddy.scanners.tls.openssl_probe._capability_io import (
    extract_libressl_version,
    extract_version,
    parse_group_list,
    run_openssl,
)
from qureddy.scanners.tls.openssl_probe._constants import (
    DEFAULT_TIMEOUT_SECONDS,
    ENV_OVERRIDE,
    HYBRID_GROUP,
    MIN_OPENSSL_VERSION,
)

_INSTALL_GUIDANCE = (
    "pip installs QuReddy, not OpenSSL. Install OpenSSL 3.5 LTS or newer separately, then pass "
    "--openssl PATH or set QUREDDY_OPENSSL. macOS: brew install openssl@3.5. "
    "Linux: install OpenSSL 3.5 LTS or newer from your distribution or trusted vendor. "
    "Windows: install a maintained OpenSSL 3.5 LTS or newer distribution and pass its full path."
)


def resolve_openssl_path(explicit: str | None) -> str:
    """Resolve ``--openssl``, then the environment override, then PATH."""
    candidate = explicit or os.environ.get(ENV_OVERRIDE) or shutil.which("openssl")
    if not candidate:
        raise LocalOpenSSLMissing(
            f"openssl binary not found on PATH or via QUREDDY_OPENSSL. {_INSTALL_GUIDANCE}",
            dependency=_missing_dependency(None),
        )
    if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
        raise LocalOpenSSLMissing(
            f"openssl path is not an executable file: {candidate}. {_INSTALL_GUIDANCE}",
            dependency=_missing_dependency(candidate),
        )
    return candidate


def _missing_dependency(path: str | None) -> OpenSSLDependency:
    return OpenSSLDependency(
        path=path,
        failure_category=FailureCategory.LOCAL_OPENSSL_MISSING,
    )


def probe_capability(
    openssl_path: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> OpenSSLDependency:
    """Return typed version and group support for a local OpenSSL binary."""
    version_text = run_openssl([openssl_path, "version"], timeout_seconds=timeout_seconds)
    groups_text = run_openssl(
        [openssl_path, "list", "-tls1_3", "-tls-groups"],
        timeout_seconds=timeout_seconds,
    )
    groups = parse_group_list(groups_text)
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
    version = extract_version(version_text)
    libressl_version = extract_libressl_version(version_text)
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
    category = dep.failure_category
    if category is FailureCategory.LOCAL_OPENSSL_BROKEN:
        raise LocalOpenSSLBroken(f"OpenSSL at {dep.path} exited nonzero", dependency=dep)
    if category is FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE:
        message = (
            f"OpenSSL at {dep.path} has unparseable version output "
            f"(required: {MIN_OPENSSL_VERSION})"
        )
        raise LocalOpenSSLVersionUnreadable(message, dependency=dep)
    if category is FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL:
        raise LocalOpenSSLIsLibreSSL(_libressl_guidance(dep), dependency=dep)
    if category is FailureCategory.LOCAL_OPENSSL_TOO_OLD:
        raise LocalOpenSSLTooOld(
            f"OpenSSL {dep.version} is below required {MIN_OPENSSL_VERSION}. {_INSTALL_GUIDANCE}",
            dependency=dep,
        )
    if category is FailureCategory.LOCAL_OPENSSL_LACKS_GROUP:
        raise LocalOpenSSLLacksGroup(
            f"OpenSSL at {dep.path} does not list {HYBRID_GROUP}",
            dependency=dep,
        )


def _libressl_guidance(dep: OpenSSLDependency) -> str:
    return (
        f"{dep.path} is LibreSSL {dep.version}, not OpenSSL — install OpenSSL "
        f"{MIN_OPENSSL_VERSION}+ with {HYBRID_GROUP}. On macOS: brew install "
        "openssl@3.5, then pass --openssl $(brew --prefix openssl@3.5)/bin/openssl "
        f"or export {ENV_OVERRIDE}=$(brew --prefix openssl@3.5)/bin/openssl."
    )
