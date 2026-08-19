# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""CLI validation, exit-code, and local-capability failure tests."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

import qureddy.cli as cli_module
import qureddy.cli.ssh as ssh_cli_module
from qureddy.cli import app, main
from qureddy.core import retry as retry_module
from tests._fake_openssl import fake_openssl


def test_invalid_target_exits_4() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", ""])
    assert result.exit_code == 4


@pytest.mark.parametrize("bad_sni", ["", " ", "   ", "\t", "\n"])
def test_empty_or_whitespace_sni_exits_4(bad_sni: str) -> None:
    """typer.testing.CliRunner no longer merges stderr into stdout (no
    mix_stderr option, unlike click.testing.CliRunner) — the error text
    lands on result.stderr, not result.stdout. See issue #189."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "tls", "example.com", "--sni", bad_sni])
    assert result.exit_code == 4
    assert "sni" in result.stderr.lower()


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
    monkeypatch.setattr("qureddy.cli.scan.parse_target", _boom)
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
    fake = fake_openssl("openssl_too_old")
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
            fake_openssl("openssl_too_old"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["summary"]["failure_category"] == "local_openssl_too_old"
    assert payload["summary"]["readiness"] == "unknown"


def test_local_openssl_version_mismatch_exits_3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A parseable release above the exact pin stays on the typed exit-3 surface."""

    def synthetic_capability_output(
        args: list[str],
        *,
        timeout_seconds: int,
    ) -> str:
        assert timeout_seconds > 0
        if args[-1] == "version":
            return "OpenSSL 3.5.8 1 Jun 2026"
        assert args[-3:] == ["list", "-tls1_3", "-tls-groups"]
        return "X25519MLKEM768:x25519"

    monkeypatch.setattr(
        "qureddy.scanners.tls.openssl_probe.capability.run_openssl",
        synthetic_capability_output,
    )
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_ok"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    dependency = payload["dependencies"][0]
    assert payload["scan"]["status"] == "local_openssl_version_mismatch"
    assert payload["summary"]["failure_category"] == "local_openssl_version_mismatch"
    assert payload["summary"]["readiness"] == "unknown"
    assert dependency["failure_category"] == "local_openssl_version_mismatch"
    assert dependency["version"] == "3.5.8"
    assert "OpenSSL 3.5.8" in result.stderr
    assert "required 3.5.7" in result.stderr
    assert "3.5.7+" not in result.stderr
    assert "or newer" not in result.stderr.lower()


def test_local_openssl_lacks_group_exits_3() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_lacks_group"),
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


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com",
        "tls://example.com",
        "ftp://example.com",
        "nonsense://example.com",
    ],
)
def test_ssh_foreign_scheme_exits_4_without_probe(
    target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Foreign URI intent is rejected before DNS, sockets, or SSH probing."""

    def unexpected_probe(*_args: object, **_kwargs: object) -> None:
        pytest.fail("SSH probe was called for a rejected target")

    monkeypatch.setattr(ssh_cli_module, "scan_ssh", unexpected_probe)
    result = CliRunner().invoke(app, ["scan", "ssh", target, "--format", "json"])
    assert result.exit_code == 4
    assert "unsupported SSH scheme" in result.stderr


def test_local_openssl_broken_exits_3() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_broken_returncode"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["scan"]["status"] == "local_openssl_broken"
    assert payload["dependencies"][0]["failure_category"] == "local_openssl_broken"
    assert payload["summary"]["failure_category"] == "local_openssl_broken"


def test_local_openssl_version_unreadable_exits_3() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_unparseable_version"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["scan"]["status"] == "local_openssl_version_unreadable"
    assert payload["dependencies"][0]["failure_category"] == "local_openssl_version_unreadable"
    assert payload["summary"]["failure_category"] == "local_openssl_version_unreadable"
