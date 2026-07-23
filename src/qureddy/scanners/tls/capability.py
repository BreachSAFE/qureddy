# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Local OpenSSL capability detection: path resolution, version, PQC groups.

Split out of openssl_probe.py per the file-size gate (coding-rules.md
§2.2) — cohesive, separable concern: "is the local OpenSSL usable"
versus openssl_probe.py's "run a TLS handshake probe against a target."
Per docs/contributors/coding-rules.md §7 and the mvp-implement skill,
subprocess calls to `openssl` live only in this module and
openssl_probe.py.
"""

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

OPENSSL_VERSION_PATTERN = re.compile(r"OpenSSL\s+(?P<version>\d+\.\d+\.\d+)")
# Apple ships LibreSSL as /usr/bin/openssl on every macOS install by
# default (issue #10); its version string ("LibreSSL 3.3.6") never
# matches OPENSSL_VERSION_PATTERN, which requires the literal "OpenSSL".
LIBRESSL_VERSION_PATTERN = re.compile(r"LibreSSL\s+(?P<version>\S+)")
ENV_OVERRIDE = "QUREDDY_OPENSSL"


def resolve_openssl_path(explicit: str | None) -> str:
    """Resolve the OpenSSL binary path: --openssl, then env var, then PATH.

    Raises:
        LocalOpenSSLMissing: When no candidate path resolves to an
            executable file. Carries an `OpenSSLDependency` so the
            caller can build a result without re-probing.
    """
    candidate = explicit or os.environ.get(ENV_OVERRIDE) or shutil.which("openssl")
    if not candidate:
        msg = "openssl binary not found on PATH or via QUREDDY_OPENSSL"
        raise LocalOpenSSLMissing(
            msg,
            dependency=OpenSSLDependency(
                path=None,
                failure_category=FailureCategory.LOCAL_OPENSSL_MISSING,
            ),
        )
    if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
        msg = f"openssl path is not an executable file: {candidate}"
        raise LocalOpenSSLMissing(
            msg,
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
    """Run capability detection.

    Returns an OpenSSLDependency describing the local install. Raises
    LocalOpenSSLTooOld or LocalOpenSSLLacksGroup if the install is
    unsuitable.
    """
    version_text = _run_openssl([openssl_path, "version"], timeout_seconds=timeout_seconds)
    version = _extract_version(version_text)
    groups_text = _run_openssl(
        [openssl_path, "list", "-tls1_3", "-tls-groups"],
        timeout_seconds=timeout_seconds,
    )
    groups = _parse_group_list(groups_text)
    supports_groups = bool(groups)
    supports_hybrid = HYBRID_GROUP.lower() in {g.lower() for g in groups}

    if version is None:
        libressl_version = _extract_libressl_version(version_text)
        if libressl_version is not None:
            return OpenSSLDependency(
                path=openssl_path,
                version=libressl_version,
                supports_tls13_groups=supports_groups,
                supports_x25519mlkem768=supports_hybrid,
                failure_category=FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL,
            )
        return OpenSSLDependency(
            path=openssl_path,
            version=None,
            supports_tls13_groups=supports_groups,
            supports_x25519mlkem768=supports_hybrid,
            failure_category=FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE,
        )

    if version < MIN_OPENSSL_VERSION:
        return OpenSSLDependency(
            path=openssl_path,
            version=str(version),
            supports_tls13_groups=supports_groups,
            supports_x25519mlkem768=supports_hybrid,
            failure_category=FailureCategory.LOCAL_OPENSSL_TOO_OLD,
        )

    if not supports_hybrid:
        return OpenSSLDependency(
            path=openssl_path,
            version=str(version),
            supports_tls13_groups=supports_groups,
            supports_x25519mlkem768=False,
            failure_category=FailureCategory.LOCAL_OPENSSL_LACKS_GROUP,
        )

    return OpenSSLDependency(
        path=openssl_path,
        version=str(version),
        supports_tls13_groups=supports_groups,
        supports_x25519mlkem768=True,
    )


def raise_if_unusable(dep: OpenSSLDependency) -> None:
    """Translate an unusable dependency into the matching exception.

    Each raised exception carries the original `OpenSSLDependency`
    so callers (e.g. the CLI) can build a capability-failure result
    without re-running capability detection.
    """
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_BROKEN:
        msg = f"OpenSSL at {dep.path} exited nonzero during capability detection"
        raise LocalOpenSSLBroken(msg, dependency=dep)
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE:
        msg = (
            f"OpenSSL at {dep.path} produced unparseable version output "
            f"(required: {MIN_OPENSSL_VERSION})"
        )
        raise LocalOpenSSLVersionUnreadable(msg, dependency=dep)
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL:
        msg = (
            f"{dep.path} is LibreSSL {dep.version}, not OpenSSL — LibreSSL does not "
            f"support the PQC groups this scanner requires (OpenSSL {MIN_OPENSSL_VERSION}+, "
            f"needed for {HYBRID_GROUP}). On macOS, install real OpenSSL and point at it "
            f"explicitly: brew install openssl@3 && qureddy scan tls <target> --openssl "
            f"$(brew --prefix openssl@3)/bin/openssl — or export "
            f"{ENV_OVERRIDE}=$(brew --prefix openssl@3)/bin/openssl once instead of "
            f"passing --openssl every time."
        )
        raise LocalOpenSSLIsLibreSSL(msg, dependency=dep)
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_TOO_OLD:
        msg = f"OpenSSL {dep.version} is below required {MIN_OPENSSL_VERSION}"
        raise LocalOpenSSLTooOld(msg, dependency=dep)
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_LACKS_GROUP:
        msg = f"OpenSSL at {dep.path} does not list {HYBRID_GROUP}"
        raise LocalOpenSSLLacksGroup(msg, dependency=dep)


def _run_openssl(args: list[str], *, timeout_seconds: int) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 -- list-form, shell=False, validated args
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
        msg = f"openssl capability check timed out: {args}"
        raise LocalOpenSSLMissing(msg) from exc
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or "(no stderr)"
        snippet = stderr[:200]
        msg = f"openssl exited with code {completed.returncode}: {snippet}"
        raise LocalOpenSSLBroken(
            msg,
            dependency=OpenSSLDependency(
                path=args[0],
                failure_category=FailureCategory.LOCAL_OPENSSL_BROKEN,
            ),
        )
    return completed.stdout


def _extract_version(text: str) -> Version | None:
    match = OPENSSL_VERSION_PATTERN.search(text)
    if not match:
        return None
    try:
        return Version(match.group("version"))
    except InvalidVersion:
        return None


def _extract_libressl_version(text: str) -> str | None:
    """Return the raw LibreSSL version string (e.g. "3.3.6"), or None.

    Kept as a plain string rather than a `packaging.version.Version`:
    LibreSSL's numbering isn't the product this scanner targets, so
    there is no "too old" comparison to make against MIN_OPENSSL_VERSION.
    """
    match = LIBRESSL_VERSION_PATTERN.search(text)
    return match.group("version") if match else None


def _parse_group_list(text: str) -> list[str]:
    """Split OpenSSL's group list into individual group names.

    Output format varies between point releases; tokenize by whitespace
    and colons rather than depending on column alignment or headers.
    """
    tokens = re.split(r"[\s:]+", text.strip())
    return [t for t in tokens if t and not t.endswith(":") and ":" not in t]
