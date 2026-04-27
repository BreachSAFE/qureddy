# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CLI smoke tests using Typer's CliRunner. No live network required."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qureddy.cli import app, main

FAKE_DIR = Path(__file__).parent / "fixtures" / "openssl" / "fake"


def test_help_lists_scan_subcommand() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout


def test_scan_help_lists_documented_options() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", "--help"])
    assert result.exit_code == 0
    assert "--sni" in result.stdout
    assert "--openssl" in result.stdout
    assert "--retry-on" in result.stdout
    assert "--retries" in result.stdout
    assert "--retry-delay" in result.stdout
    assert "--json-logs" in result.stdout


def test_invalid_target_exits_4() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", ""])
    assert result.exit_code == 4


def test_unknown_retry_category_exits_4() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--retry-on",
            "no_such_category",
            "--retries",
            "1",
        ],
    )
    assert result.exit_code == 4


def test_non_retryable_category_exits_4() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--retry-on",
            "local_openssl_missing",
            "--retries",
            "1",
        ],
    )
    assert result.exit_code == 4


def test_retries_without_retry_on_exits_4() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", "tls", "example.com", "--retries", "2"],
    )
    assert result.exit_code == 4


def test_retries_above_max_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    """`--retries 11` is rejected by Typer's min=/max= validator.

    Click signals UsageError (exit 2 in raw mode); the project entry
    point `qureddy.cli:main` translates that to exit 4. Test via
    `main()` to exercise the production path — the install-time
    console-script is what end users hit.
    """
    monkeypatch.setattr(
        "sys.argv",
        [
            "qureddy",
            "scan",
            "tls",
            "example.com",
            "--retry-on",
            "tls_handshake_failed",
            "--retries",
            "11",
        ],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 4


def test_retry_delay_above_max_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    """`--retry-delay 100` is rejected by Typer's max= validator (max 10)."""
    monkeypatch.setattr(
        "sys.argv",
        [
            "qureddy",
            "scan",
            "tls",
            "example.com",
            "--retry-on",
            "tls_handshake_failed",
            "--retries",
            "1",
            "--retry-delay",
            "100",
        ],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 4


def test_local_openssl_too_old_exits_3() -> None:
    """UC4: Detect Unsupported Local OpenSSL — exit 3."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            str(FAKE_DIR / "openssl_too_old.sh"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["summary"]["failure_category"] == "local_openssl_too_old"
    assert payload["summary"]["readiness"] == "unknown"


def test_json_output_clean_when_stderr_redirected_to_stdout() -> None:
    """JSON stdout stays parseable when CliRunner merges stderr into stdout."""
    runner = CliRunner(mix_stderr=True)
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            str(FAKE_DIR / "openssl_too_old.sh"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["summary"]["failure_category"] == "local_openssl_too_old"
    assert "scan.local_dependency_unusable" not in result.stdout


def test_local_openssl_lacks_group_exits_3() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            str(FAKE_DIR / "openssl_lacks_group.sh"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["summary"]["failure_category"] == "local_openssl_lacks_group"


def test_local_openssl_missing_exits_3() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            "/this/path/does/not/exist/openssl",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["summary"]["failure_category"] == "local_openssl_missing"


def test_json_output_top_level_keys_in_locked_order() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            str(FAKE_DIR / "openssl_too_old.sh"),
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
            str(FAKE_DIR / "openssl_too_old.sh"),
        ],
    )
    assert "QuReddy 0.1.0 by BreachSAFE OSS" in result.stdout
    assert "tls://example.com:443" in result.stdout


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
            str(FAKE_DIR / "openssl_too_old.sh"),
            "--format",
            "yaml",
        ],
    )
    # Click rejects the invalid enum value before the command body runs.
    assert result.exit_code != 0
    output = (result.stdout or "") + str(result.exception or "")
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
        tmp_path: Path,
    ) -> None:
        """Capability check is two subprocess calls (`openssl version` +
        `openssl list -tls1_3 -tls-groups`). If the CLI re-probed in the
        catch block we'd see four lines in the counter file.
        """
        counter = tmp_path / "calls.txt"
        fake = tmp_path / "fake_openssl_too_old.sh"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            f'echo "$@" >> "{counter}"\n'
            'case "$1" in\n'
            '    version) echo "OpenSSL 3.4.0 1 Jan 2026" ;;\n'
            "    list) echo '  x25519:secp256r1' ;;\n"
            "    *) exit 2 ;;\n"
            "esac\n",
        )
        fake.chmod(0o755)

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "scan",
                "tls",
                "example.com",
                "--openssl",
                str(fake),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 3, result.stdout
        invocations = counter.read_text().splitlines()
        assert len(invocations) == 2, (
            f"capability check ran {len(invocations)} times, expected 2 — "
            f"CLI is re-probing instead of consuming exc.dependency. "
            f"calls: {invocations}"
        )
