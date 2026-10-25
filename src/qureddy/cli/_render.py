# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Output-format dispatch and output-file handling for the scan commands."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import IO

from qureddy.cli._errors import EXIT_INTERNAL_ERROR, EXIT_USAGE, _fail
from qureddy.core.models import OutputFormat, ScanResult, Severity
from qureddy.output.cbom import build_cbom_payload, render_cbom, render_cbom_payload
from qureddy.output.console import render_rich
from qureddy.output.json import render_json
from qureddy.output.jsonl import render_jsonl
from qureddy.output.markdown import render_cbom_markdown, render_markdown


def _open_output_file(output: Path | None) -> IO[str] | None:
    """Open the ``--output`` destination for writing; return None when unset.

    A path that cannot be opened is a usage error (exit 4), reported before any
    scan work — the same failure contract as ``--log`` in ``scan.py``. The
    caller owns the returned stream and closes it.
    """
    if output is None:
        return None
    try:
        return output.open("w", encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write --output file {output}: {exc.strerror or exc}", EXIT_USAGE)


def _prepare_output_dir(output_dir: Path | None, output: Path | None) -> None:
    """Validate and create a bundle directory before scan work begins."""
    if output_dir is None:
        return
    if output is not None:
        _fail("--output and --output-dir cannot be used together", EXIT_USAGE)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _fail(f"cannot create --output-dir {output_dir}: {exc.strerror or exc}", EXIT_USAGE)


def _render_bundle(
    result: ScanResult,
    output_dir: Path,
    *,
    reproducible: bool,
    compact: bool,
) -> None:
    """Publish every projection as one complete, rollback-safe bundle.

    The destination is prepared before scanning, so it already exists when
    this function is called.  Rendered files are written to a private staging
    directory first.  Commit replaces the public files only after every write
    succeeds; a failure restores the previous bundle and never leaves a new
    partial bundle visible.  ``manifest.json`` is the completion marker and
    records hashes for the published artifacts.
    """
    files = _render_projection_files(result, reproducible=reproducible, compact=compact)
    stage: Path | None = None
    backup: Path | None = None
    preserve_backup = False
    installed: list[Path] = []
    try:
        stage = _stage_bundle(output_dir, files)
        backup = Path(tempfile.mkdtemp(prefix=".qureddy-backup-", dir=output_dir))
        _install_staged_bundle(output_dir, stage, files, backup, installed)
    except OSError as exc:
        preserve_backup, rollback_error = _rollback_bundle(output_dir, backup, installed)
        if rollback_error is not None:
            _fail(rollback_error, EXIT_INTERNAL_ERROR)
        if not preserve_backup:
            backup = None
        _fail(
            f"cannot publish scan bundle in {output_dir}: {exc.strerror or exc}",
            EXIT_INTERNAL_ERROR,
        )
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        if backup is not None and not preserve_backup:
            shutil.rmtree(backup, ignore_errors=True)


def _render_projection_files(
    result: ScanResult, *, reproducible: bool, compact: bool
) -> dict[str, str]:
    """Render every bundle projection from one canonical result."""
    json_stream = io.StringIO()
    cbom_stream = io.StringIO()
    jsonl_stream = io.StringIO()
    rich_stream = io.StringIO()
    markdown_stream = io.StringIO()
    render_json(result, json_stream, compact=compact)
    cbom_payload = build_cbom_payload(result, reproducible=reproducible)
    render_cbom_payload(cbom_payload, cbom_stream, compact=compact)
    render_jsonl(result, jsonl_stream)
    render_rich(result, rich_stream)
    render_markdown(result, markdown_stream)
    cbom_markdown = io.StringIO()
    render_cbom_markdown(cbom_payload, cbom_markdown)
    files = {
        "scan.json": json_stream.getvalue(),
        "scan.cdx.json": cbom_stream.getvalue(),
        "scan.jsonl": jsonl_stream.getvalue(),
        "scan.rich.txt": rich_stream.getvalue(),
        "scan.md": markdown_stream.getvalue(),
        "cbom.md": cbom_markdown.getvalue(),
    }
    certificate_pem = _certificate_text(result)
    if certificate_pem is not None:
        files["certificate.pem"] = certificate_pem
    return files


def _stage_bundle(output_dir: Path, files: dict[str, str]) -> Path:
    """Write all projections and their manifest into a private stage."""
    stage = Path(tempfile.mkdtemp(prefix=".qureddy-bundle-", dir=output_dir))
    try:
        for name, content in files.items():
            (stage / name).write_text(content, encoding="utf-8")
        manifest = _bundle_manifest(stage, files)
        (stage / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )
    except OSError:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return stage


def _install_staged_bundle(
    output_dir: Path,
    stage: Path,
    files: dict[str, str],
    backup: Path,
    installed: list[Path],
) -> None:
    """Replace managed files while exposing partial progress to rollback."""
    # ``certificate.pem`` is managed even when this scan has no certificate;
    # moving it into the rollback directory removes stale evidence safely.
    managed_names = dict.fromkeys((*files, "manifest.json", "certificate.pem"))
    for name in managed_names:
        destination = output_dir / name
        if destination.exists():
            destination.replace(backup / name)
        if name in files or name == "manifest.json":
            (stage / name).replace(destination)
            installed.append(destination)


def _rollback_bundle(
    output_dir: Path, backup: Path | None, installed: list[Path]
) -> tuple[bool, str | None]:
    """Restore a prior bundle and report whether a failed restore needs preserving."""
    try:
        for destination in installed:
            destination.unlink(missing_ok=True)
        if backup is not None:
            for saved in backup.iterdir():
                saved.replace(output_dir / saved.name)
    except OSError as rollback_exc:
        backup_location = backup if backup is not None else output_dir
        return (
            True,
            f"cannot publish scan bundle in {output_dir}; rollback failed "
            f"({rollback_exc}) - originals kept in {backup_location}",
        )
    if backup is not None:
        shutil.rmtree(backup, ignore_errors=True)
    return False, None


def _certificate_text(result: ScanResult) -> str | None:
    """Return the observed leaf PEM without adding it to machine results."""
    certificate_pem = next(
        (e.certificate_pem for e in result.evidence if e.certificate_pem is not None), None
    )
    return None if certificate_pem is None else certificate_pem + "\n"


def _bundle_manifest(stage: Path, files: dict[str, str]) -> dict[str, object]:
    """Build the completion manifest from bytes already written to staging."""
    artifacts = []
    for name in files:
        data = (stage / name).read_bytes()
        artifacts.append(
            {
                "name": name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return {
        "schema_version": "qureddy.output_bundle.v1",
        "status": "complete",
        "artifacts": artifacts,
    }


def _render(
    result: ScanResult,
    output_format: OutputFormat,
    verbose: int,
    *,
    reproducible: bool = False,
    compact: bool = False,
    min_severity: Severity | None = None,
    stream: IO[str] | None = None,
    output_dir: Path | None = None,
) -> None:
    """Dispatch to the JSON, CBOM, JSONL, Markdown, or Rich renderer.

    ``stream`` defaults to the current ``sys.stdout``; ``--output`` supplies a
    file stream instead, which keeps stdout empty (and byte-clean) for the
    machine formats. ``compact`` minifies the JSON/CBOM document; ``min_severity``
    trims the human findings table only — the machine document stays complete
    (issue #30 machine-purity contract).
    """
    if output_dir is not None:
        _render_bundle(result, output_dir, reproducible=reproducible, compact=compact)
        return
    target = stream if stream is not None else sys.stdout
    if output_format is OutputFormat.JSON:
        render_json(result, target, compact=compact)
    elif output_format is OutputFormat.CBOM:
        render_cbom(result, target, reproducible=reproducible, compact=compact)
    elif output_format is OutputFormat.JSONL:
        render_jsonl(result, target)
    elif output_format is OutputFormat.MARKDOWN:
        render_markdown(result, target)
    else:
        render_rich(result, target, verbosity=verbose, min_severity=min_severity)
