# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bounded adapter for the external ``cbomkit-theia`` artifact scanner.

    structured source ──▶ list-form argv ──▶ bounded subprocess
          │                                      │
          └── target validation                  ├── stdout: CycloneDX CBOM
                                                 └── stderr/status: failure

Theia already owns artifact discovery and CycloneDX serialization.  QuReddy
therefore validates and carries the document as opaque bytes; it does not
reclassify components into a second crypto model or silently turn a tool
failure into a successful scan.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from functools import cached_property
from pathlib import Path

from qureddy.core.contracts import (
    Capability,
    CollectionFailure,
    CollectionFailureKind,
    CollectionResult,
    ScanSource,
    SourceKind,
)
from qureddy.scanners.common.process import run_bounded

_DEFAULT_OUTPUT_LIMIT = 32 * 1024 * 1024
_VERSION_TIMEOUT_SECONDS = 5
_IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9./:@_-]{0,4095}$")


class CbomkitTheiaAdapter:
    """Run one validated Theia ``dir`` or ``image`` scan.

    The executable is optional, like ``ike-scan``.  ``QUREDDY_THEIA`` may
    select an explicit binary; otherwise PATH resolution is used.  Every
    invocation uses ``shell=False``, a closed stdin, a wall-clock deadline,
    and a combined stdout/stderr byte budget.
    """

    tool_id = "cbomkit-theia"
    capabilities = frozenset({Capability.CONTAINER_IMAGE, Capability.FILESYSTEM_DIRECTORY})

    def __init__(
        self,
        binary_name: str | None = None,
        *,
        output_limit: int = _DEFAULT_OUTPUT_LIMIT,
    ) -> None:
        """Configure binary discovery and the maximum captured output size."""
        if output_limit < 1:
            raise ValueError("output_limit must be at least 1")
        self._binary_name = binary_name or os.environ.get("QUREDDY_THEIA", "cbomkit-theia")
        self._output_limit = output_limit

    @cached_property
    def _binary(self) -> str | None:
        """Resolve the configured executable once for this adapter instance."""
        candidate = Path(self._binary_name).expanduser()
        if candidate.is_absolute():
            return str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else None
        return shutil.which(self._binary_name)

    @cached_property
    def version(self) -> str:
        """Return the first bounded version line, or ``unknown`` if unavailable."""
        if self._binary is None:
            return "unknown"
        try:
            output = run_bounded(
                [self._binary, "--version"],
                timeout_seconds=_VERSION_TIMEOUT_SECONDS,
                output_limit=4096,
            )
        except OSError:
            return "unknown"
        if output.return_code != 0 or output.timed_out or output.output_limited:
            return "unknown"
        text = (output.stdout or output.stderr).decode("utf-8", errors="replace")
        return text.splitlines()[0].strip() if text.splitlines() else "unknown"

    def available(self) -> bool:
        """Return whether the configured executable is present and executable."""
        return self._binary is not None

    def run(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        """Run Theia and return its validated CycloneDX bytes or typed failure."""
        prepared = self._prepare(source)
        if isinstance(prepared, CollectionResult):
            return prepared
        mode, binary = prepared
        return self._execute(binary, mode, source.locator, timeout_seconds=timeout_seconds)

    def _prepare(self, source: ScanSource) -> tuple[str, str] | CollectionResult:
        """Validate source and resolve the executable before child-process work."""
        mode = _mode_for(source)
        if mode is None:
            return self._failure(
                CollectionFailureKind.UNSUPPORTED, "source is not a Theia artifact"
            )
        if not self.available():
            return self._failure(CollectionFailureKind.UNAVAILABLE, "cbomkit-theia is unavailable")
        validation_error = _validate_reference(source, mode)
        if validation_error is not None:
            return self._failure(CollectionFailureKind.MALFORMED, validation_error)
        binary = self._binary
        if binary is None:  # The availability check above is a typed race-safe guard.
            return self._failure(CollectionFailureKind.UNAVAILABLE, "cbomkit-theia is unavailable")
        return mode, binary

    def _execute(
        self, binary: str, mode: str, locator: str, *, timeout_seconds: int
    ) -> CollectionResult:
        """Execute a prepared request and validate only its stdout document."""
        try:
            output = run_bounded(
                [binary, mode, locator],
                timeout_seconds=timeout_seconds,
                output_limit=self._output_limit,
            )
        except OSError as exc:
            return self._failure(CollectionFailureKind.EXECUTION, str(exc))
        if output.timed_out:
            return self._failure(CollectionFailureKind.TIMEOUT, "cbomkit-theia timed out")
        if output.output_limited:
            return self._failure(
                CollectionFailureKind.MALFORMED, "cbomkit-theia output exceeded limit"
            )
        if output.return_code != 0:
            return self._failure(CollectionFailureKind.EXECUTION, "cbomkit-theia exited nonzero")
        error = _validate_cbom(output.stdout)
        if error is not None:
            return self._failure(CollectionFailureKind.MALFORMED, error)
        return CollectionResult(
            collector=self.tool_id,
            collector_version=self.version,
            artifact_cbom=output.stdout,
        )

    def _failure(self, kind: CollectionFailureKind, message: str) -> CollectionResult:
        """Return a typed failure without exposing unbounded tool output."""
        return CollectionResult(
            collector=self.tool_id,
            collector_version=self.version,
            failure=CollectionFailure(kind=kind, message=message),
        )


def _mode_for(source: ScanSource) -> str | None:
    """Map the source vocabulary to Theia's two artifact subcommands."""
    return {
        SourceKind.CONTAINER_IMAGE: "image",
        SourceKind.FILESYSTEM_DIRECTORY: "dir",
    }.get(source.kind)


def _validate_reference(source: ScanSource, mode: str) -> str | None:
    """Reject impossible or unsafe references before invoking Theia."""
    if not source.locator or source.locator != source.locator.strip():
        return "Theia reference must be non-empty and have no surrounding whitespace"
    if mode == "dir":
        path = Path(source.locator).expanduser()
        if not path.is_dir():
            return "Theia directory reference is not a directory"
        if not os.access(path, os.R_OK | os.X_OK):
            return "Theia directory reference is not readable"
        return None
    if source.locator.startswith("/") or not _IMAGE_REFERENCE.fullmatch(source.locator):
        return "Theia image reference is not a valid OCI reference"
    return None


def _validate_cbom(document: bytes) -> str | None:
    """Require a JSON CycloneDX document before returning it to a caller."""
    try:
        payload = json.loads(document)
    except (UnicodeDecodeError, json.JSONDecodeError):  # fmt: skip
        return "cbomkit-theia stdout is not valid JSON"
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        return "cbomkit-theia stdout is not a CycloneDX document"
    if not isinstance(payload.get("specVersion"), str):
        return "CycloneDX document has no specVersion"
    return None
