# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Machine-output purity: --format json/cbom emits exactly one parseable document.

Issue #30 contract: in machine formats the structured document plus the
process exit code carry the failure; operator diagnostics on stderr must
never corrupt a genuine fd-level `2>&1` pipeline, while separate streams
(and rich mode) keep the actionable stderr hint from issue #274.

The subprocess tests drive the installed `qureddy` entrypoint because
CliRunner cannot simulate `2>&1`: the shell merges fd 1/2 via dup2()
before Python starts. Same rationale as the companion tests in
tests/test_cli.py (issues #189/#194).
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import qureddy.cli._errors as errors_module
from qureddy.cli import app
from qureddy.cli._errors import _echo_operator_diagnostic, _stderr_merged_into_stdout
from tests._fake_openssl import fake_openssl

# Resolved once to a full path so subprocess calls below satisfy Bandit's
# S607 (partial executable path), matching tests/test_cli.py.
_QUREDDY_BIN = shutil.which("qureddy") or "qureddy"
_SUBPROCESS_INJECT_DIR = Path(__file__).parent.parent / "subprocess_inject"
# Generous ceiling: every scenario here fails fast (fake openssl binary or
# refused loopback connect); the timeout only guards against a hang.
_SUBPROCESS_TIMEOUT = 60


def _raise_probe_failure() -> bool:
    """Windows-only helper: force `_windows_standard_handles_match` to fail so
    the real-fd-but-undetermined path is exercised on nt as well (#344 item 2)."""
    raise OSError("handle probe unavailable")


def _without_document_identity(output: str) -> str:
    """Normalize the per-run document-identity values allowed to vary.

    Besides the CycloneDX serialNumber and emission timestamp, the CBOM carries the
    scan id and scan start/finish times (#152) and per-probe wall-clock durations
    (evidence.NN.duration_ms) — all run-identity/timing, not content — so they are
    normalized here to keep the final-bytes-repeatable contract meaningful (#176/#208).
    """
    output = re.sub(
        r'("serialNumber": )"urn:uuid:[^"]+"',
        r'\1"<document-serial>"',
        output,
    )
    output = re.sub(
        r'("timestamp": )"[^"]+"',
        r'\1"<document-timestamp>"',
        output,
    )
    output = re.sub(
        r'("name": "qureddy:scan\.(?:id|started_at|completed_at)",\s*"value": )"[^"]*"',
        r'\1"<run-identity>"',
        output,
    )
    # Per-probe duration_ms is wall-clock timing — non-deterministic run to run
    # (the flaky field behind #176/#208). Since #307 it rides in the occurrence
    # additionalContext k=v grammar as "duration_ms=<n>" (previously a flat
    # qureddy:evidence.NN.duration_ms property); normalize it in that location.
    return re.sub(r"duration_ms=\d+", "duration_ms=<duration>", output)


def _run_qureddy(
    *args: str,
    merge_stderr: bool,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the installed qureddy binary, optionally with fd-level `2>&1`."""
    return subprocess.run(  # noqa: S603 -- list-form, shell=False, resolved full path
        [_QUREDDY_BIN, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
        encoding="utf-8",
        check=False,
        timeout=_SUBPROCESS_TIMEOUT,
        env=env,
    )


def _refused_loopback_target() -> str:
    """A loopback host:port that refuses connections (hermetic, no network).

    Binds an ephemeral port to learn a currently-free port number, then
    releases it — connecting immediately after gets ECONNREFUSED.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"127.0.0.1:{port}"


_TLS_EXIT3_ARGS = (
    "scan",
    "tls",
    "example.com",
    "--openssl",
    fake_openssl("openssl_too_old"),
)


def test_installed_cbom_final_bytes_are_repeatable() -> None:
    """The installed console produces identical bytes except document identity."""
    outputs: list[str] = []
    for _ in range(2):
        result = _run_qureddy(
            "scan",
            "tls",
            "192.0.2.1",
            "--openssl",
            fake_openssl("openssl_connect_refused"),
            "--format",
            "cbom",
            merge_stderr=False,
        )
        assert result.returncode == 2
        assert result.stderr == ""
        assert json.loads(result.stdout)["specVersion"] == "1.7"
        outputs.append(result.stdout)

    assert _without_document_identity(outputs[0]) == _without_document_identity(outputs[1])


def test_installed_classical_cbom_final_bytes_include_certificate() -> None:
    """A successful installed scan emits repeatable references and certificate bytes."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SUBPROCESS_INJECT_DIR)
    env["QUREDDY_TEST_FORCE_CLASSICAL_RESULT"] = "1"
    outputs: list[str] = []
    for _ in range(2):
        result = _run_qureddy(
            "scan",
            "tls",
            "classical.example.invalid",
            "--format",
            "cbom",
            merge_stderr=False,
            env=env,
        )
        assert result.returncode == 0
        assert result.stderr == ""
        payload = json.loads(result.stdout)
        assert payload["metadata"]["component"]["bom-ref"] == "endpoint"
        dependencies = {item["ref"]: item for item in payload["dependencies"]}
        assert dependencies["endpoint"]["provides"] == [
            "crypto/algorithm/ecdsa-with-sha256",
            "crypto/algorithm/tls_aes_256_gcm_sha384",
            "crypto/algorithm/x25519",
            "crypto/certificate/leaf",
            "crypto/protocol/tls-tlsv1.3",
        ]
        certificate = next(
            item for item in payload["components"] if item["bom-ref"] == "crypto/certificate/leaf"
        )
        properties = certificate["cryptoProperties"]["certificateProperties"]
        assert properties["serialNumber"] == "0123456789ABCDEF"
        assert properties["subjectName"] == "CN=classical.example.invalid"
        outputs.append(result.stdout)

    assert _without_document_identity(outputs[0]) == _without_document_identity(outputs[1])


@pytest.mark.parametrize("output_format", ["json", "cbom"])
@pytest.mark.parametrize("quiet", [True, False])
def test_machine_output_clean_under_2and1_on_capability_failure(
    output_format: str, quiet: bool
) -> None:
    """Exit-3 path: stdout alone is one parseable document under real `2>&1`."""
    args = [*_TLS_EXIT3_ARGS, "--format", output_format]
    if quiet:
        args.append("--quiet")
    result = _run_qureddy(*args, merge_stderr=True)
    assert result.returncode == 3
    payload = json.loads(result.stdout)
    if output_format == "json":
        assert payload["summary"]["failure_category"] == "local_openssl_too_old"
    else:
        assert payload["bomFormat"] == "CycloneDX"


@pytest.mark.parametrize("output_format", ["json", "cbom"])
@pytest.mark.parametrize("quiet", [True, False])
def test_machine_output_keeps_stderr_hint_with_separate_streams(
    output_format: str, quiet: bool
) -> None:
    """Separate fds keep the actionable hint, including with --quiet."""
    args = [*_TLS_EXIT3_ARGS, "--format", output_format]
    if quiet:
        args.append("--quiet")
    result = _run_qureddy(*args, merge_stderr=False)
    assert result.returncode == 3
    json.loads(result.stdout)
    assert "qureddy:" in result.stderr, (
        f"exit 3 with empty stderr in --format {output_format} despite separate streams"
    )


def test_machine_verbose_diagnostics_stay_on_stderr() -> None:
    """Explicit -v in machine format: logs go to stderr, stdout stays clean.

    The documented escape hatch: -v wins over the machine-format quiet
    default, and the user keeps clean JSON by keeping the streams separate.
    """
    result = _run_qureddy(*_TLS_EXIT3_ARGS, "--format", "json", "-v", merge_stderr=False)
    assert result.returncode == 3
    json.loads(result.stdout)
    assert "qureddy:" in result.stderr


@pytest.mark.parametrize("output_format", ["json", "cbom"])
def test_typed_scan_error_emits_document_under_2and1(output_format: str) -> None:
    """Installed subprocess preserves a document and exit 2 for typed failures."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SUBPROCESS_INJECT_DIR)
    env["QUREDDY_TEST_FORCE_TYPED_ERROR"] = "1"
    result = _run_qureddy(
        "scan",
        "tls",
        "example.com",
        "--format",
        output_format,
        merge_stderr=True,
        env=env,
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    if output_format == "json":
        assert payload["summary"]["failure_category"] == "target_scan_failed"
    else:
        assert payload["bomFormat"] == "CycloneDX"


@pytest.mark.parametrize("output_format", ["json", "cbom"])
def test_ssh_probe_failure_emits_one_document_under_2and1(
    output_format: str,
) -> None:
    """SSH probe failure in machine formats: one parseable document, exit 2.

    Regression for the TLS/SSH asymmetry found in the #30 audit: `scan ssh`
    used to print only a stderr line and leave stdout completely empty.
    """
    result = _run_qureddy(
        "scan",
        "ssh",
        _refused_loopback_target(),
        "--format",
        output_format,
        merge_stderr=True,
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    if output_format == "json":
        assert payload["summary"]["failure_category"] == "target_connect_failed"
        assert payload["summary"]["readiness"] == "unknown"
        assert payload["scan"]["scanner_name"] == "ssh"
    else:
        assert payload["bomFormat"] == "CycloneDX"


def test_ssh_probe_failure_json_carries_hint_with_separate_streams() -> None:
    """SSH machine-format failure keeps the operator hint when fds are separate."""
    result = _run_qureddy(
        "scan",
        "ssh",
        _refused_loopback_target(),
        "--format",
        "json",
        merge_stderr=False,
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["summary"]["failure_category"] == "target_connect_failed"
    assert "ssh scan failed" in result.stderr


def test_ssh_probe_failure_rich_mode_unchanged() -> None:
    """Rich mode keeps the pre-existing contract: stderr message, exit 2."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "ssh", _refused_loopback_target()])
    assert result.exit_code == 2
    assert "ssh scan failed" in result.stderr


class TestStderrMergedDetection:
    """Unit tests for the fd-identity guard behind the `2>&1` suppression."""

    def test_true_when_both_streams_share_one_open_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with (tmp_path / "merged.log").open("w") as stream:
            monkeypatch.setattr(sys, "stdout", stream)
            monkeypatch.setattr(sys, "stderr", stream)
            if os.name == "nt":
                monkeypatch.setattr(errors_module, "_windows_standard_handles_match", lambda: True)
            assert _stderr_merged_into_stdout() is True

    def test_false_for_separate_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with (
            (tmp_path / "out.log").open("w") as out_stream,
            (tmp_path / "err.log").open("w") as err_stream,
        ):
            monkeypatch.setattr(sys, "stdout", out_stream)
            monkeypatch.setattr(sys, "stderr", err_stream)
            if os.name == "nt":
                monkeypatch.setattr(errors_module, "_windows_standard_handles_match", lambda: False)
            assert _stderr_merged_into_stdout() is False

    def test_false_for_streams_without_a_file_descriptor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CliRunner/pytest-style in-process streams must never suppress."""
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        monkeypatch.setattr(sys, "stderr", io.StringIO())
        assert _stderr_merged_into_stdout() is False

    def test_no_real_fd_stays_fail_open_even_in_machine_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#344 item 2 boundary: an in-process stream (fileno() raises) has no
        fd-level table to have been merged, so it must fail *open* (return
        False) regardless of `default_when_undetermined`. This is what keeps
        the CliRunner/pytest hint visible."""
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        monkeypatch.setattr(sys, "stderr", io.StringIO())
        assert _stderr_merged_into_stdout() is False
        assert _stderr_merged_into_stdout(default_when_undetermined=True) is False

    def test_fails_closed_when_real_fd_stat_is_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#344 item 2: with real file descriptors present but introspection
        (`os.fstat`) failing, machine mode must fail *closed* — assume merged
        and suppress — rather than risk leaking into the machine document."""

        def _fstat_boom(_fd: int) -> object:
            raise OSError("fstat unavailable")

        with (
            (tmp_path / "out.log").open("w") as out_stream,
            (tmp_path / "err.log").open("w") as err_stream,
        ):
            monkeypatch.setattr(sys, "stdout", out_stream)
            monkeypatch.setattr(sys, "stderr", err_stream)
            monkeypatch.setattr(errors_module.os, "fstat", _fstat_boom)
            if os.name == "nt":
                monkeypatch.setattr(
                    errors_module, "_windows_standard_handles_match", _raise_probe_failure
                )
            # Historical default (fail open) when undetermined.
            assert _stderr_merged_into_stdout() is False
            # Machine mode opts into fail-closed.
            assert _stderr_merged_into_stdout(default_when_undetermined=True) is True

    def test_diagnostic_suppressed_in_machine_mode_when_stat_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#344 item 2: the operator diagnostic is suppressed in a machine
        format when real-fd introspection fails, and still printed in rich
        mode."""

        def _fstat_boom(_fd: int) -> object:
            raise OSError("fstat unavailable")

        monkeypatch.setattr(errors_module.os, "fstat", _fstat_boom)
        if os.name == "nt":
            monkeypatch.setattr(
                errors_module, "_windows_standard_handles_match", _raise_probe_failure
            )
        err_path = tmp_path / "err.log"

        with err_path.open("w") as err_stream:
            monkeypatch.setattr(sys, "stderr", err_stream)
            _echo_operator_diagnostic("boom-machine", machine_format=True)
        assert "boom-machine" not in err_path.read_text()

        with err_path.open("w") as err_stream:
            monkeypatch.setattr(sys, "stderr", err_stream)
            _echo_operator_diagnostic("boom-rich", machine_format=False)
        assert "boom-rich" in err_path.read_text()
