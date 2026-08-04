# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""CLI output-format and capability-failure rendering tests."""

from __future__ import annotations

import json
import re
import subprocess
from urllib.parse import urlsplit

import pytest
from typer.testing import CliRunner

import qureddy.scanners.tls.openssl_probe._capability_io as capability_io
from qureddy._branding import HEADER
from qureddy.cli import _render as render_module
from qureddy.cli import app, main
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

        monkeypatch.setattr(capability_io.subprocess, "run", run_fake)
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
