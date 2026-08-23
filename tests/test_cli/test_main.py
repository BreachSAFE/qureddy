# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CLI smoke tests using Typer's CliRunner. No live network required."""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from typer.testing import CliRunner

from qureddy import __version__
from qureddy._branding import VERSION_BANNER
from qureddy.cli import app, main


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
    assert "--deterministic" in result.stdout
    assert "--output-dir" in result.stdout
    assert "--reproducible" not in result.stdout


def test_deterministic_flag_and_deprecated_alias_enable_same_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The old spelling remains a hidden compatibility alias for one cycle."""
    runner = CliRunner()
    calls: list[bool] = []

    def fake_scan_and_render(**kwargs: object) -> int:
        calls.append(bool(kwargs["reproducible"]))
        return 0

    monkeypatch.setattr("qureddy.cli.scan._scan_and_render", fake_scan_and_render)
    for flag in ("--deterministic", "--reproducible"):
        result = runner.invoke(app, ["scan", "tls", "example.com", flag])
        assert result.exit_code == 0, result.output
    assert calls == [True, True]


def test_scan_tls_help_carries_examples_block() -> None:
    """Issue #41 / ADR 0003 Pattern 3: EXAMPLES block on every subcommand."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", "--help"])
    assert result.exit_code == 0
    assert "EXAMPLES" in result.stdout
    assert any(
        line.strip() == "qureddy scan tls google.com" for line in result.stdout.splitlines()
    ), "expected the google.com example"


def _line_with_substring(stdout: str, needle: str) -> str:
    """Return the (stripped) line containing `needle`, or '' if absent."""
    for line in stdout.split("\n"):
        if needle in line:
            return line.strip()
    return ""


def test_scan_tls_help_examples_render_one_per_line() -> None:
    """Issue #71: comments and commands render on separate lines.

    The pre-fix bug collapsed every single newline to a space, so a
    `# comment` line followed by a `qureddy scan tls ...` line rendered
    as `# comment ... qureddy scan tls ...` on a single output line.

    The strong assertion: NO line in the help output contains BOTH a
    `#` comment marker AND a `qureddy scan tls` command invocation.
    Catches comment-merged-with-command for any example in the EXAMPLES
    block, not just the named ones — so adding a 5th example wouldn't
    silently regress.
    """
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", "--help"])
    assert result.exit_code == 0

    for line in result.stdout.split("\n"):
        # In a properly-rendered EXAMPLES block, comment lines and command
        # lines never share a single output line.
        if "# " in line and "qureddy scan tls" in line:
            raise AssertionError(f"comment merged with command on one line: {line.strip()!r}")

    # Also lock that each named example's command appears in the output.
    for cmd in (
        "qureddy scan tls google.com",
        "qureddy scan tls pq.cloudflareresearch.com",
        "qureddy scan tls 1.1.1.1:443",
        "qureddy scan tls flaky.example.com",
    ):
        assert cmd in result.stdout, f"missing example command: {cmd}"


def test_scan_tls_help_carries_exit_codes_block() -> None:
    """Issue #41 / ADR 0003 Pattern 4: EXIT CODES block in epilog."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", "--help"])
    assert result.exit_code == 0
    assert "EXIT CODES" in result.stdout
    assert "scan succeeded" in result.stdout
    assert "target scan failed" in result.stdout
    assert "local dependency" in result.stdout
    assert "usage" in result.stdout.lower()


def test_scan_tls_help_exit_codes_render_one_per_line() -> None:
    """Issue #71: each exit code (0/2/3/4/70) on a distinct line.

    Pre-fix, all five codes ran together on one line. A user trying to
    scan the table couldn't tell which description belongs to which
    code. Lock that the exit-code rows split on rendering.
    """
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", "--help"])
    assert result.exit_code == 0

    succeeded = _line_with_substring(result.stdout, "scan succeeded")
    assert succeeded, "exit-code 0 row not found"
    # "scan succeeded" must NOT share a line with "target scan failed" (code 2).
    assert "target scan failed" not in succeeded, (
        f"exit codes 0 and 2 collapsed onto one line: {succeeded!r}"
    )

    target = _line_with_substring(result.stdout, "target scan failed")
    assert "local dependency" not in target, (
        f"exit codes 2 and 3 collapsed onto one line: {target!r}"
    )

    local = _line_with_substring(result.stdout, "local dependency")
    assert "usage" not in local.lower() or "EX_SOFTWARE" in local or local.endswith("3.5)"), (
        f"exit codes 3 and 4 collapsed onto one line: {local!r}"
    )

    internal = _line_with_substring(result.stdout, "EX_SOFTWARE")
    assert internal, "exit-code 70 (EX_SOFTWARE) row not found"


def test_scan_tls_help_carries_environment_block() -> None:
    """Issue #41 / ADR 0003 Pattern 4: ENVIRONMENT block in epilog."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", "--help"])
    assert result.exit_code == 0
    assert "ENVIRONMENT" in result.stdout
    assert "NO_COLOR" in result.stdout
    assert "QUREDDY_OPENSSL" in result.stdout


def test_scan_tls_help_environment_renders_one_per_line() -> None:
    """Issue #71: NO_COLOR and QUREDDY_OPENSSL appear on distinct lines."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", "--help"])
    assert result.exit_code == 0

    no_color = _line_with_substring(result.stdout, "NO_COLOR")
    assert no_color, "NO_COLOR row not found"
    assert "QUREDDY_OPENSSL" not in no_color, (
        f"NO_COLOR and QUREDDY_OPENSSL collapsed onto one line: {no_color!r}"
    )

    qureddy_openssl = _line_with_substring(result.stdout, "QUREDDY_OPENSSL")
    assert qureddy_openssl, "QUREDDY_OPENSSL row not found"


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
    name_and_version, separator, url = VERSION_BANNER.partition(" -- ")
    assert separator == " -- ", "expected '--' separator (not em-dash)"
    assert name_and_version == f"BreachSAFE QuReddy {__version__}"
    parsed_url = urlsplit(url)
    assert parsed_url.scheme == "https"
    assert parsed_url.hostname == "www.breachsafe.ai"
    assert parsed_url.path in ("", "/")


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


@pytest.mark.parametrize("bad_flag", ["--v", "--vv", "--vvv", "--vvvv"])
def test_double_dash_v_typo_emits_helpful_hint(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    bad_flag: str,
) -> None:
    """Issue #74: `--v`/`--vv`/`--vvv` typos emit a hint about single-dash form.

    Click's default error reads `No such option: --vvv` with no hint
    that the verbosity flag is `-vvv` (single dash). Replace with an
    actionable hint that names both the short and long form.
    """
    monkeypatch.setattr(
        "sys.argv",
        ["qureddy", "scan", "tls", "example.com", bad_flag],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 4
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    # Hint must reference the single-dash form so the user knows what to type.
    assert "-v" in combined, f"missing -v hint for {bad_flag}: {combined!r}"
    # Hint should call out the dash-confusion explicitly so the user
    # understands why their input was wrong, not just what to type instead.
    assert "single" in combined.lower() or "single-dash" in combined.lower(), (
        f"hint should mention single-dash for {bad_flag}: {combined!r}"
    )


def test_verbose_typo_emits_helpful_hint(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Issue #74: `--verbos` (typo missing `e`) gets the same hint."""
    monkeypatch.setattr(
        "sys.argv",
        ["qureddy", "scan", "tls", "example.com", "--verbos"],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 4
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    # Same strong assertion as the dash-confusion tests: explicit
    # mention of "single-dash" so the user understands the issue.
    assert "single" in combined.lower() or "single-dash" in combined.lower(), (
        f"hint should mention single-dash for --verbos: {combined!r}"
    )


def test_unrelated_v_word_does_not_trigger_verbosity_hint(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Issue #74: `--view` (legitimate word starting with v) does NOT get the hint.

    The detector targets verbosity-shaped typos specifically; unrelated
    flag typos like `--view`, `--variable` should fall through to
    Click's default "No such option" without our extra hint. Otherwise
    every flag-starting-with-v typo would suggest the user wanted
    verbosity, which is wrong.
    """
    monkeypatch.setattr(
        "sys.argv",
        ["qureddy", "scan", "tls", "example.com", "--view"],
    )
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 4
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    # Default Click error must fire; OUR hint must NOT.
    assert "No such option" in combined
    assert "single-dash" not in combined.lower(), (
        f"unrelated --view typo got verbosity hint: {combined!r}"
    )


def test_scan_tls_bad_log_path_is_usage_error_not_traceback(tmp_path) -> None:
    """A --log path that cannot be opened is a usage error (exit 4), never a traceback.

    Filesystem failures vary by OS (FileExistsError, IsADirectoryError, NotADirectoryError,
    PermissionError); the guard catches their common base OSError, so the exit is 4 on any
    platform regardless of errno. The open fails before any scan, so no network is used.
    """
    a_file = tmp_path / "a_file"
    a_file.write_text("x")  # a regular file; using it as a parent directory must fail
    result = CliRunner().invoke(
        app, ["scan", "tls", "example.com", "--log", str(a_file / "sub.log")]
    )
    assert result.exit_code == 4, result.output
    assert "Traceback" not in result.output
