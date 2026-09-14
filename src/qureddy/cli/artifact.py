# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The ``qureddy scan dir|image`` artifact commands.

Theia owns the artifact CBOM schema and serialization.  These commands expose
that authoritative document directly; they deliberately do not manufacture a
second ``ScanResult`` with empty network findings just to fit the endpoint
renderers.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import structlog
import typer

from qureddy.cli._errors import EXIT_TARGET_FAILED, EXIT_USAGE, _fail
from qureddy.cli._help import _NO_WRAP_CONTEXT_SETTINGS, _colorize_help_text
from qureddy.cli.main import scan_app
from qureddy.core.contracts import ScanSource, SourceKind
from qureddy.core.logging import start_run_logging
from qureddy.scanners.artifact import CbomkitTheiaAdapter

_ARTIFACT_EPILOG = _colorize_help_text("""\
OUTPUT:

\b
The command writes Theia's CycloneDX CBOM to stdout. Diagnostics stay on stderr.
Use --output to save the CBOM without mixing it with terminal output.

\b
Theia dir scans artifact files in a directory; it is not source-code AST analysis.
Use CBOMkit's Sonar Cryptography integration for source-code scanning.
""")

ArtifactReference = Annotated[str, typer.Argument(help="Directory path or OCI image reference.")]
ArtifactTimeout = Annotated[
    int,
    typer.Option("--timeout", min=1, max=300, help="Theia subprocess timeout in seconds."),
]
ArtifactOutput = Annotated[
    Path | None,
    typer.Option("--output", help="Write Theia's CycloneDX CBOM to this file."),
]


def _scan_artifact(kind: SourceKind, reference: str, timeout: int, output: Path | None) -> None:
    """Run one Theia artifact scan and preserve its CBOM bytes exactly."""
    # Machine output must remain byte-clean: the shared subprocess runner logs
    # process lifecycle events, so use the established quiet mode before the
    # opaque CycloneDX bytes are written to stdout.
    log_stream = start_run_logging(verbosity=0, json_logs=False, quiet=True, log=None)
    try:
        result = CbomkitTheiaAdapter().run(
            ScanSource(kind=kind, locator=reference), timeout_seconds=timeout
        )
    finally:
        structlog.contextvars.clear_contextvars()
        if log_stream is not None:
            log_stream.close()
    if result.failure is not None:
        typer.echo(result.failure.message, err=True)
        raise typer.Exit(code=EXIT_TARGET_FAILED)
    if result.artifact_cbom is None:
        typer.echo("cbomkit-theia returned no CBOM", err=True)
        raise typer.Exit(code=EXIT_TARGET_FAILED)
    if output is None:
        sys.stdout.buffer.write(result.artifact_cbom)
        if not result.artifact_cbom.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        return
    try:
        output.write_bytes(result.artifact_cbom)
    except OSError as exc:
        _fail(f"cannot write --output file {output}: {exc.strerror or exc}", EXIT_USAGE)


@scan_app.command("dir", epilog=_ARTIFACT_EPILOG, context_settings=_NO_WRAP_CONTEXT_SETTINGS)
def scan_directory(
    reference: ArtifactReference,
    timeout: ArtifactTimeout = 120,
    output: ArtifactOutput = None,
) -> None:
    """Scan artifact files in a directory with bundled cbomkit-theia."""
    _scan_artifact(SourceKind.FILESYSTEM_DIRECTORY, reference, timeout, output)


@scan_app.command("image", epilog=_ARTIFACT_EPILOG, context_settings=_NO_WRAP_CONTEXT_SETTINGS)
def scan_image(
    reference: ArtifactReference,
    timeout: ArtifactTimeout = 120,
    output: ArtifactOutput = None,
) -> None:
    """Scan a container image with bundled cbomkit-theia."""
    _scan_artifact(SourceKind.CONTAINER_IMAGE, reference, timeout, output)
