# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""OpenSSL 3.5+ subprocess probe.

Per docs/contributors/coding-rules.md §7 and the mvp-implement skill, this module is
the only place in the codebase that calls `openssl` via `subprocess`.
Other modules consume typed `OpenSSLDependency` and `ProbeResult` values.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime

from packaging.version import InvalidVersion, Version

from qureddy.core.errors import (
    LocalOpenSSLBroken,
    LocalOpenSSLLacksGroup,
    LocalOpenSSLMissing,
    LocalOpenSSLTooOld,
    LocalOpenSSLVersionUnreadable,
)
from qureddy.core.logging import get_logger
from qureddy.core.models import (
    FailureCategory,
    OpenSSLDependency,
    ProbeCommand,
    ProbeResult,
)
from qureddy.scanners.tls._classify import classify_failure

_log = get_logger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30
MIN_OPENSSL_VERSION = Version("3.5.0")
HYBRID_GROUP = "X25519MLKEM768"
CLASSICAL_GROUP = "X25519"
EXCERPT_LIMIT = 4096

OPENSSL_VERSION_PATTERN = re.compile(r"OpenSSL\s+(?P<version>\d+\.\d+\.\d+)")
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
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_TOO_OLD:
        msg = f"OpenSSL {dep.version} is below required {MIN_OPENSSL_VERSION}"
        raise LocalOpenSSLTooOld(msg, dependency=dep)
    if dep.failure_category is FailureCategory.LOCAL_OPENSSL_LACKS_GROUP:
        msg = f"OpenSSL at {dep.path} does not list {HYBRID_GROUP}"
        raise LocalOpenSSLLacksGroup(msg, dependency=dep)


def run_hybrid_probe(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    attempt_number: int = 1,
) -> ProbeResult:
    """Run X25519MLKEM768 probe against host:port."""
    args = _build_probe_args(openssl_path, host, port, sni, group=HYBRID_GROUP)
    return _run_probe(args, timeout_seconds=timeout_seconds, attempt_number=attempt_number)


def run_classical_probe(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    attempt_number: int = 1,
) -> ProbeResult:
    """Run classical X25519 control probe."""
    args = _build_probe_args(openssl_path, host, port, sni, group=CLASSICAL_GROUP)
    return _run_probe(args, timeout_seconds=timeout_seconds, attempt_number=attempt_number)


def _build_probe_args(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    group: str,
) -> list[str]:
    args = [
        openssl_path,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-tls1_3",
        "-groups",
        group,
        "-brief",
    ]
    if sni is not None:
        args.extend(["-servername", sni])
    return args


def _run_probe(
    args: list[str],
    *,
    timeout_seconds: int,
    attempt_number: int,
) -> ProbeResult:
    """Execute a single OpenSSL probe and return a typed `ProbeResult`."""
    started = datetime.now(UTC)
    _log_subprocess_start(args, timeout_seconds, attempt_number)
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
    except subprocess.TimeoutExpired as exc:
        return _probe_result_from_timeout(args, exc, started, timeout_seconds, attempt_number)
    except FileNotFoundError as exc:
        raise LocalOpenSSLMissing(str(exc)) from exc

    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    failure = classify_failure(completed.stderr) if completed.returncode != 0 else None
    _log_subprocess_complete(args, completed.returncode, duration_ms, attempt_number, failure)
    # `openssl s_client -brief` writes summary lines to stderr; concatenate
    # so downstream parsers see one stream regardless of which OpenSSL chose.
    combined_excerpt = (completed.stdout + completed.stderr)[:EXCERPT_LIMIT]
    return _build_probe_result(
        args=args,
        stdout=completed.stdout,
        stderr=completed.stderr,
        stdout_excerpt=combined_excerpt,
        return_code=completed.returncode,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        timeout_seconds=timeout_seconds,
        failure_category=failure,
    )


def _log_subprocess_start(args: list[str], timeout_seconds: int, attempt_number: int) -> None:
    _log.debug(
        "subprocess.start",
        executable=args[0],
        args=tuple(args[1:]),
        timeout_seconds=timeout_seconds,
        attempt_number=attempt_number,
    )


def _log_subprocess_complete(
    args: list[str],
    return_code: int,
    duration_ms: int,
    attempt_number: int,
    failure: FailureCategory | None,
) -> None:
    _log.debug(
        "subprocess.complete",
        executable=args[0],
        args=tuple(args[1:]),
        return_code=return_code,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        failure_category=failure.value if failure else None,
    )


def _probe_result_from_timeout(
    args: list[str],
    exc: subprocess.TimeoutExpired,
    started: datetime,
    timeout_seconds: int,
    attempt_number: int,
) -> ProbeResult:
    """Build a ProbeResult from a TimeoutExpired, preserving partial output.

    `subprocess.TimeoutExpired` carries any output the process produced
    before the kill. Preserve it for forensics — a connection that wrote
    half a handshake before stalling tells a different story from one
    that wrote nothing.
    """
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    partial_stdout = _decode_partial(exc.stdout)
    partial_stderr = _decode_partial(exc.stderr)
    timeout_marker = f"\n[qureddy] timeout after {timeout_seconds}s"
    stderr_with_marker = (
        partial_stderr + timeout_marker if partial_stderr else timeout_marker.lstrip("\n")
    )
    return _build_probe_result(
        args=args,
        stdout=partial_stdout,
        stderr=partial_stderr,
        stdout_excerpt=partial_stdout[:EXCERPT_LIMIT],
        stderr_excerpt_override=stderr_with_marker[:EXCERPT_LIMIT],
        return_code=-1,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        timeout_seconds=timeout_seconds,
        failure_category=FailureCategory.TLS_HANDSHAKE_FAILED,
    )


def _build_probe_result(
    *,
    args: list[str],
    stdout: str,
    stderr: str,
    stdout_excerpt: str,
    return_code: int,
    duration_ms: int,
    attempt_number: int,
    timeout_seconds: int,
    failure_category: FailureCategory | None,
    stderr_excerpt_override: str | None = None,
) -> ProbeResult:
    """Build a ProbeResult from raw bytes + status fields.

    Hashes the unmodified stdout/stderr (so SHA-256 reflects what the
    process emitted, not our annotations). The caller may override
    `stderr_excerpt` (e.g., to append a `[qureddy] timeout after Ns`
    marker) without affecting the hash.
    """
    return ProbeResult(
        command=ProbeCommand(
            executable=args[0],
            args=tuple(args[1:]),
            timeout_seconds=timeout_seconds,
        ),
        return_code=return_code,
        stdout_sha256=hashlib.sha256(stdout.encode("utf-8", "replace")).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode("utf-8", "replace")).hexdigest(),
        stdout_excerpt=stdout_excerpt,
        stderr_excerpt=stderr_excerpt_override
        if stderr_excerpt_override is not None
        else stderr[:EXCERPT_LIMIT],
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        failure_category=failure_category,
    )


# Re-exported so existing tests at tests/test_openssl_probe.py that
# import _classify_failure from this module keep working unchanged.
# Canonical implementation lives in `_classify.py`.
_classify_failure = classify_failure


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


def _parse_group_list(text: str) -> list[str]:
    """Split OpenSSL's group list into individual group names.

    Output format varies between point releases; tokenize by whitespace
    and colons rather than depending on column alignment or headers.
    """
    tokens = re.split(r"[\s:]+", text.strip())
    return [t for t in tokens if t and not t.endswith(":") and ":" not in t]


def _decode_partial(value: bytes | str | None) -> str:
    """Decode partial subprocess output captured on TimeoutExpired.

    `subprocess.run(..., text=True)` normally returns str, but when
    `TimeoutExpired` fires `exc.stdout`/`exc.stderr` may be bytes (the
    default capture type) regardless of `text=True` — the conversion
    only runs on successful completion. We accept all three shapes
    (bytes, str, None) so the timeout branch never crashes when
    different Python or platform versions surface different types.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
