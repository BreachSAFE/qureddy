# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CLI smoke tests using Typer's CliRunner. No live network required."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import qureddy.cli as cli_module
from qureddy import __version__
from qureddy.cli import VERSION_BANNER, app, main
from qureddy.core import retry as retry_module

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


def test_version_flag_emits_banner() -> None:
    """Issue #41: --version prints `<name> <version> -- <url>` and exits 0."""
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == VERSION_BANNER


def test_short_v_flag_also_works() -> None:
    """Issue #41: -V is parity with --version."""
    runner = CliRunner()
    result = runner.invoke(app, ["-V"])
    assert result.exit_code == 0
    assert result.stdout.strip() == VERSION_BANNER


def test_version_banner_includes_breachsafe_name_and_url() -> None:
    """Issue #41: banner format is `BreachSAFE QuReddy <version> -- <url>`.

    Locks the format so a future refactor can't drop the project name
    or URL without breaking this test. Uses `--` (double-hyphen) per
    coding-rules §18 (no em-dashes in source).
    """
    assert "BreachSAFE QuReddy" in VERSION_BANNER
    assert __version__ in VERSION_BANNER
    assert "https://www.breachsafe.ai" in VERSION_BANNER
    assert " -- " in VERSION_BANNER, "expected '--' separator (not em-dash)"


def test_version_on_subcommand_suggests_root_form(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`qureddy scan tls TARGET --version` errors helpfully, not cryptically.

    Click's default error is `No such option: --version` because the
    flag is registered at the root callback only (matches git/docker/gh
    convention). That default is unhelpful — replace with a hint that
    points at `qureddy --version`.
    """
    monkeypatch.setattr(
        "sys.argv",
        ["qureddy", "scan", "tls", "example.com", "--version"],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 4
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    # The hint must reference the root-level flag explicitly so the user
    # knows where it lives, not just that the current placement is wrong.
    assert "qureddy --version" in combined, f"expected 'qureddy --version' hint, got: {combined!r}"


def test_version_on_scan_subcommand_only_also_suggests_root_form(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Same hint when --version lands on `qureddy scan` (no subsubcommand)."""
    monkeypatch.setattr(
        "sys.argv",
        ["qureddy", "scan", "--version"],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 4
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "qureddy --version" in combined


def test_invalid_target_exits_4() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", ""])
    assert result.exit_code == 4


@pytest.mark.parametrize("bad_sni", ["", " ", "   ", "\t", "\n"])
def test_empty_or_whitespace_sni_exits_4(bad_sni: str) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", "example.com", "--sni", bad_sni])
    assert result.exit_code == 4
    assert "sni" in result.stdout.lower()


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


def test_retry_constants_are_canonical_in_core_retry() -> None:
    """Issue #46: the retry bounds live in `core.retry` only.

    Both Typer (CLI option `min=`/`max=`) and `validate_retry_args` must
    read the same constants. Defining them twice (once in `cli.py`,
    once in `core/retry.py`) creates a future drift risk where the
    Typer guard and the validator report different boundaries.
    """
    # Local duplicates removed from cli.py.
    assert not hasattr(cli_module, "_MAX_RETRIES"), (
        "_MAX_RETRIES still defined in cli.py — should import from core.retry"
    )
    assert not hasattr(cli_module, "_MAX_RETRY_DELAY_SECONDS"), (
        "_MAX_RETRY_DELAY_SECONDS still defined in cli.py — should import from core.retry"
    )

    # cli.py's references resolve to the canonical objects in core.retry,
    # not local shadows. Identity (`is`) — not equality — catches the
    # `MAX_RETRIES = 3` shadow case where a future contributor re-defines
    # the constant at cli.py module scope without the underscore.
    # Note: CPython interns small ints (-5..256), so an idempotent
    # `MAX_RETRIES = 3` re-definition with the same int value passes
    # identity by accident. The `not hasattr(_MAX_RETRIES)` guard above
    # catches the underscore-prefixed shape; this `is` check catches
    # any drift to a different value (or a non-cached float).
    assert cli_module.MAX_RETRIES is retry_module.MAX_RETRIES
    assert cli_module.MAX_RETRY_DELAY_SECONDS is retry_module.MAX_RETRY_DELAY_SECONDS


def test_main_exits_70_on_internal_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Issue #12: an internal qureddy bug must not exit 2 (target failed).

    BSD `sysexits.h` reserves 70 (`EX_SOFTWARE`) for "internal software
    error". A CI script branching on \\$? == 2 should be able to trust
    that 2 means "the target scan failed", not "qureddy crashed". Force
    `scan_tls` to raise a non-QureddyError; the top-level `except
    Exception` arm in `main()` must route to exit 70, not 2.
    """

    def _boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("simulated internal qureddy bug")

    # Patch parse_target — called early in scan_tls, before any exception
    # handling. A non-QureddyError raised here flows up through main()'s
    # last-resort `except Exception`, which is the path issue #12 fixes.
    monkeypatch.setattr("qureddy.cli.parse_target", _boom)
    monkeypatch.setattr(
        "sys.argv",
        ["qureddy", "scan", "tls", "example.com", "--format", "json"],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 70, (
        f"main() exited {exit_info.value.code}, expected 70 (EX_SOFTWARE) — "
        "internal errors must not collide with target-scan-failed (2)"
    )
    captured = capsys.readouterr()
    assert "unexpected error" in captured.err
    assert "simulated internal qureddy bug" in captured.err


def test_main_exits_3_on_capability_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = str(FAKE_DIR / "openssl_too_old.sh")
    monkeypatch.setattr(
        "sys.argv",
        ["qureddy", "scan", "tls", "example.com", "--openssl", fake, "--format", "json"],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 3


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
