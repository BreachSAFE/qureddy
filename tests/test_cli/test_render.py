# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CLI output-format and capability-failure rendering tests."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from typer.testing import CliRunner

from qureddy._branding import HEADER
from qureddy.cli import _render as render_module
from qureddy.cli import app, main
from qureddy.scanners.tls.openssl_probe import executor
from tests._fake_openssl import fake_openssl


def test_json_output_top_level_keys_in_locked_order() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
            "--format",
            "json",
        ],
    )
    payload = json.loads(result.stdout)
    expected = [
        "schema_version",
        "scan",
        "target",
        "dependencies",
        "assets",
        "evidence",
        "findings",
        "summary",
    ]
    assert list(payload.keys()) == expected


def test_output_dir_emits_correlated_json_and_cbom_from_one_scan(tmp_path: Path) -> None:
    """Issue #430: bundle projections retain one scan identity and observation window."""
    run_dir = tmp_path / "run"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
            "--output-dir",
            str(run_dir),
        ],
    )
    assert result.exit_code == 3, result.output
    json_payload = json.loads((run_dir / "scan.json").read_text(encoding="utf-8"))
    cbom_payload = json.loads((run_dir / "scan.cdx.json").read_text(encoding="utf-8"))
    properties = {item["name"]: item["value"] for item in cbom_payload["metadata"]["properties"]}
    assert cbom_payload["specVersion"] == "1.7"
    assert json_payload["scan"]["scan_id"] == properties["qureddy:scan.id"]
    for field in ("started_at", "completed_at"):
        json_time = datetime.fromisoformat(json_payload["scan"][field].replace("Z", "+00:00"))
        cbom_time = datetime.fromisoformat(properties[f"qureddy:scan.{field}"])
        assert json_time == cbom_time
    jsonl_lines = (run_dir / "scan.jsonl").read_text(encoding="utf-8").splitlines()
    assert all(
        json.loads(line)["info"]["metadata"]["scan_id"] == json_payload["scan"]["scan_id"]
        for line in jsonl_lines
    )
    assert (run_dir / "scan.rich.txt").read_text(encoding="utf-8").startswith("QuReddy")


def test_jsonl_format_emits_one_machine_record_per_finding() -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
            "--format",
            "jsonl",
        ],
    )
    assert result.exit_code == 3, result.output
    lines = result.stdout.splitlines()
    assert lines
    records = [json.loads(line) for line in lines]
    assert len(records) == len({record["finding_hash"] for record in records})
    for record in records:
        assert record["type"] == "ssl"
        assert record["info"]["metadata"]["scan_id"]
        assert record["info"]["metadata"]["scanner_version"]


def test_output_dir_cannot_be_combined_with_output(tmp_path: Path) -> None:
    """Bundle mode rejects ambiguous destinations before running a scan."""
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--output",
            str(tmp_path / "scan.json"),
            "--output-dir",
            str(tmp_path / "run"),
        ],
    )
    assert result.exit_code == 4
    assert "cannot be used together" in (result.stdout + result.stderr)


def test_output_dir_creation_failure_is_usage_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bundle setup reports a destination error before scanning."""

    def fail_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        raise OSError(13, "permission denied")

    monkeypatch.setattr(Path, "mkdir", fail_mkdir)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--output-dir",
            str(tmp_path / "run"),
        ],
    )
    assert result.exit_code == 4
    assert "cannot create --output-dir" in (result.stdout + result.stderr)


def test_output_bundle_write_failure_is_usage_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bundle persistence errors remain distinct from scan failures."""
    fake = fake_openssl("openssl_too_old")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    def fail_write_text(self: Path, *args: object, **kwargs: object) -> int:
        raise OSError(28, "no space left on device")

    monkeypatch.setattr(Path, "write_text", fail_write_text)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake,
            "--output-dir",
            str(run_dir),
        ],
    )
    assert result.exit_code == 4
    assert "cannot write scan bundle" in (result.stdout + result.stderr)


def test_rich_format_renders_header() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
        ],
    )
    assert HEADER in result.stdout
    rendered_urls = {
        urlsplit(match.group(0))
        for match in re.finditer(r"[a-z][a-z0-9+.-]*://[A-Za-z0-9.-]+(?::[0-9]+)?", result.stdout)
    }
    assert urlsplit("tls://example.com:443") in rendered_urls


def test_invalid_format_value_is_rejected() -> None:
    """Bad --format input must not silently fall back to Rich.

    Typer rejects values outside the OutputFormat enum (rich | json)
    with a click.UsageError. The CliRunner sees Click's exit code 2;
    the install entrypoint (`qureddy.cli:main`) re-translates Click
    UsageErrors to exit code 4.
    """
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
            "--format",
            "yaml",
        ],
    )
    # Click rejects the invalid enum value before the command body runs.
    # typer.testing.CliRunner no longer merges stderr into stdout (no
    # mix_stderr option) — the error text lands on result.stderr. See #189.
    assert result.exit_code != 0
    output = (result.stdout or "") + (result.stderr or "")
    assert "yaml" in output.lower() or "format" in output.lower()


def test_invalid_format_via_main_exits_4(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`qureddy.cli:main` translates Click UsageError to exit code 4.

    Verifying via the project's installed entry point (not CliRunner)
    so the documented exit-code surface (4 = usage/configuration
    error) is exercised end-to-end.
    """
    monkeypatch.setattr(
        "sys.argv",
        ["qureddy", "scan", "tls", "example.com", "--format", "yaml"],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 4
    captured = capsys.readouterr()
    assert (
        "yaml" in (captured.err + captured.out).lower()
        or "format" in (captured.err + captured.out).lower()
    )


def test_invalid_retries_via_main_exits_4(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-integer --retries value triggers exit 4 via main()."""
    monkeypatch.setattr(
        "sys.argv",
        ["qureddy", "scan", "tls", "example.com", "--retries", "notanint"],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 4


class TestCapabilityFailureNoDoubleProbe:
    """The CLI's capability-failure handler must consume the
    OpenSSLDependency the original probe already populated, NOT re-run
    probe_capability. Re-running:

      - wastes a subprocess invocation, and
      - opens a TOCTOU window where a second probe could see different
        state than the first.

    Reviewer-flagged bug. This test counts subprocess invocations via
    a fake openssl that tallies its calls.
    """

    def test_local_too_old_runs_capability_check_only_once(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Capability check is two subprocess calls (`openssl version` +
        `openssl list -tls1_3 -tls-groups`). If the CLI re-probed in the
        catch block we'd see four lines in the counter file.
        """
        invocations: list[list[str]] = []

        def run_fake(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            invocations.append(args)
            stdout = "OpenSSL 3.4.0 1 Jan 2026" if args[1] == "version" else "x25519"
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

        # #296: the single subprocess boundary now lives in the executor.
        monkeypatch.setattr(executor.subprocess, "run", run_fake)
        fake = fake_openssl("openssl_too_old")

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "scan",
                "tls",
                "example.com",
                "--openssl",
                fake,
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 3, result.stdout
        assert len(invocations) == 2, (
            f"capability check ran {len(invocations)} times, expected 2 — "
            f"CLI is re-probing instead of consuming exc.dependency. "
            f"calls: {invocations}"
        )


def test_cbom_capability_failure_has_no_certificate_observation() -> None:
    """A rejected OpenSSL cannot yield a captured certificate observation."""
    assert not hasattr(render_module, "_fetch_cert_for_cbom"), (
        "CBOM rendering must not perform a second certificate fetch"
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_libressl"),
            "--format",
            "cbom",
        ],
    )
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    cert_components = [
        c
        for c in payload.get("components", [])
        if c.get("cryptoProperties", {}).get("assetType") == "certificate"
    ]
    assert cert_components == [], "capability-failure CBOM must not contain a certificate component"


@pytest.mark.parametrize("output_format", ["json", "cbom"])
def test_machine_formats_emit_stderr_hint_on_capability_failure(
    output_format: str,
) -> None:
    """Issue #274: exit 3 must explain itself on stderr even in machine formats.

    `--format json/cbom` defaults to quiet logging so stdout stays a clean
    machine document — but that suppressed the only user-facing report of
    the capability failure (`log.warning`), leaving exit 3 with an empty
    stderr. The actionable message must be a direct stderr echo, exempt
    from the machine-format quiet default, like the exit-2/exit-4 paths.
    """
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_libressl"),
            "--format",
            output_format,
        ],
    )
    assert result.exit_code == 3
    assert "LibreSSL" in result.stderr, (
        f"exit 3 with empty/unhelpful stderr in --format {output_format}: {result.stderr!r}"
    )
