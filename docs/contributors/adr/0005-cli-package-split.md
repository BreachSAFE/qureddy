<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR 0005 — Split `cli.py` into a `cli/` package before MVP 0.2

**Status:** Proposed
**Date:** 2026-04-27
**Deciders:** Paul Volosen, project lead
**Consulted:** Claude (drafting), Codex (architect / arbiter)
**Informed:** MVP 0.2+ contributors
**Supersedes:** none
**Superseded by:** none
**Tracking issue:** [#60](https://github.com/paul007ex/qureddy/issues/60)
**Related:** [ADR 0003](0003-cli-help-rewrite.md), [ADR 0004](0004-multi-scanner-architecture.md), [#41](https://github.com/paul007ex/qureddy/issues/41), [#42](https://github.com/paul007ex/qureddy/issues/42), [#43](https://github.com/paul007ex/qureddy/issues/43), [#44](https://github.com/paul007ex/qureddy/issues/44), [#45](https://github.com/paul007ex/qureddy/issues/45)

---

## Context

`src/qureddy/cli.py` is **421 lines** as of HEAD on `fix/75-root-verbosity-flags`. `coding-rules.md` Rule 2.1 caps files at 400 lines hard ceiling. The file is already in violation.

It contains, at last audit, the following load-bearing concerns in one module:

- **Branding constants** (project name, URL, license, version banner)
- **Annotated option types** (~12 `TargetArg`, `SniOpt`, `FormatOpt`, `OpenSSLOpt`, `TimeoutOpt`, `RetryOnOpt`, `RetriesOpt`, `RetryDelayOpt`, `VerboseOpt`, `JsonLogsOpt`, `QuietOpt`)
- **Help-text and version callbacks** (`_version_callback`, ADR 0003 epilog blocks)
- **App + scan-app Typer setup**
- **The `_root` function** (114 LOC — massively over Rule 2.2's 50-line ceiling)
- **The `scan_tls` command body** (40 LOC, in the danger zone)
- **The `main()` entry-point wrapper** (89 LOC — over Rule 2.2)
- **Two Click error-classifier helpers** (`_is_version_misplacement`, `_is_verbosity_dash_confusion`)
- **Three near-identical `try/except/typer.Exit` ladders** (catching `RetryConfigError`, `TargetParseError`, `QureddyError`)
- **Render dispatch** (`_render`, `_execute_scan`, `_parse_retry_args`, `_parse_cli_target`)

Forecast through MVP 0.2-1.0:

| Milestone | What lands in `cli.py` | LOC delta |
|---|---|---|
| **Today** | (above) | **421** |
| #41 v1 remaining (slices 2-4) | banner formatter, epilog blocks, expanded option help text | +100 |
| **#42-#45** (ADR 0003 follow-ups) | `--help-all`, no-args overview, POSIX synopsis, `qureddy help <cmd>` | +270 |
| **MVP 0.2** (`scan cert`) | new subcommand + cert-specific options | +50 |
| **MVP 0.3** (`emit cbom`) | new top-level command | +20 |
| **MVP 0.4** (`scan ssh`) | new subcommand | +50 |
| **MVP 0.5/0.6** (`scan config`, `scan source`) | two more subcommands | +100 |
| **Total at MVP 0.6** |  | **~1,011** |

`cli.py` is past 400 today and trending toward ~1,000+ LOC by MVP 0.6. The structural decision is **not whether** to split — it's **when**.

This ADR locks the *shape* of the split so the implementation PR (tracked in #60) is mechanical.

## Decision

Refactor `src/qureddy/cli.py` into a `src/qureddy/cli/` package, organized by **purpose**, not by **subcommand**. Subcommands fan out into per-scanner files only when MVP 0.2 introduces the second one.

### Target structure

```
src/qureddy/cli/
├── __init__.py        # Re-exports `app`, `main` for entry-point compatibility.
│                      # ~10 lines. Public API surface: only what was exported before.
│
├── _branding.py       # PROJECT_NAME, PROJECT_URL, SOURCE_URL, LICENSE_NAME,
│                      # VERSION_BANNER, _version_callback. ADR 0003 §"Branding".
│                      # ~40 lines. Read by _help.py, main.py.
│
├── _options.py        # Module-level Annotated option aliases:
│                      # TargetArg, SniOpt, OpenSSLOpt, FormatOpt, TimeoutOpt,
│                      # RetryOnOpt, RetriesOpt, RetryDelayOpt, VerboseOpt,
│                      # JsonLogsOpt, QuietOpt.
│                      # ~80 lines. Read by every command module.
│
├── _help.py           # Epilog strings, examples blocks, retry-on/--verbose
│                      # detailed help text per ADR 0003.
│                      # ~80 lines. Read by main.py and scan.py.
│
├── _errors.py         # _fail(msg, code) helper consolidating the three
│                      # try/except/typer.Exit ladders. Click error
│                      # classifier helpers.
│                      # ~60 lines. Read by main.py and scan.py.
│
├── main.py            # app = typer.Typer(...), scan_app = typer.Typer(...),
│                      # _root() callback, main() entry-point wrapper.
│                      # ~150 lines. Top-level glue only — no command logic.
│
└── scan.py            # @scan_app.command("tls") body and orchestration:
│                      # _execute_scan, _parse_retry_args, _parse_cli_target,
│                      # _render. ~150 lines. Becomes a sibling of cli/cert.py
│                      # at MVP 0.2.
```

### Naming and module conventions

- **Underscore-prefixed modules** (`_branding`, `_options`, `_help`, `_errors`) are private to the package. Tests import them via the parent package only when necessary; `__all__` in `__init__.py` does not re-export them.
- **`main.py` and `scan.py`** are the package's public-shaped modules. Subcommands are top-level (`scan.py`, `cert.py` at 0.2, `ssh.py` at 0.4) — *not* nested under `cli/scan/` — because each subcommand is one file at the layer below `app`.
- **`__init__.py`** re-exports exactly two names (`app`, `main`) for backward compatibility with `pyproject.toml`'s `[project.scripts]` (`qureddy = "qureddy.cli:main"`) and `src/qureddy/__main__.py`'s `from qureddy.cli import main`.

### Why this shape (vs. alternatives)

**Considered: split by subcommand only (`cli/scan_tls.py`, `cli/main.py`).** Rejected — duplicates the option-alias declarations across every subcommand file. MVP 0.2's `cli/scan_cert.py` would re-declare `OpenSSLOpt`, `FormatOpt`, etc. for cert-specific options that overlap.

**Considered: keep one file but cap line count via aggressive helper extraction in-module.** Rejected — fights the file-size limit instead of fixing the structural problem. Helpers don't change the fact that `cli.py` is doing nine concerns.

**Considered: split into `cli/` and a separate `branding/` top-level package.** Rejected — branding is CLI-presentation-only; it doesn't belong at the top of the package tree alongside `core/`, `output/`, `scanners/`.

### Sub-task: extract `_fail(msg, code)` helper

Three near-identical `try/except/typer.Exit` blocks in `cli.py` collapse into a single helper in `cli/_errors.py`:

```python
def _fail(msg: str, code: int) -> None:
    """Echo `msg` to stderr and exit with `code`. Used by error handlers."""
    typer.echo(f"qureddy: {msg}", err=True)
    raise typer.Exit(code=code)
```

Each call site changes from:

```python
except RetryConfigError as exc:
    typer.echo(f"qureddy: {exc}", err=True)
    raise typer.Exit(code=EXIT_USAGE) from None
```

to:

```python
except RetryConfigError as exc:
    _fail(str(exc), EXIT_USAGE)
```

Saves ~6 lines, gives a single boundary for future "JSON-mode error formatting" or other cross-cutting changes. Documented in #60's tracking comment.

## Why this fits the project

**`coding-rules.md` Rule 2.1** explicitly anticipates this kind of split:

> *"The TLS scanner directory has separate files (`scanner.py`, `openssl_probe.py`, `parse.py`) instead of one `tls.py` for exactly this reason."*

The same logic applies to `cli.py`: when one module accumulates more than one concern, the right answer is a package, not aggressive helper extraction.

**ADR 0004 (multi-scanner architecture)** introduces a `Scanner(Protocol)` and a per-scanner registry. Each scanner gets its own subcommand: `scan tls`, `scan cert`, `scan ssh`, etc. The CLI organization should mirror the scanner organization — one file per subcommand at MVP 0.2 onward.

**The `cli/` package name is consistent** with the existing `scanners/tls/`, `core/`, and `output/` packages. No new top-level concept is introduced.

## Roadmap fit

- [x] **MVP 0.1 / pre-MVP 0.2** — best window. The refactor is mechanical: move constants/options/helpers into separate files; `__init__.py` re-exports for entry-point compatibility. Doing it before MVP 0.2's `scan cert` lands means MVP 0.2's PR is purely about the cert scanner, not about CLI-restructure-plus-cert.
- **#41 v1 remaining slices (2-4)** — currently planned to land in `cli.py`; should land in `cli/_branding.py`, `cli/_help.py` instead. **Sequencing: this ADR's PR lands first.**
- **#42, #43, #44, #45** — ADR 0003 follow-up subcommands. Each becomes a small addition in `cli/_help.py` or `cli/main.py`. **Sequencing: after this ADR's PR.**
- **MVP 0.2 (`scan cert`)** — adds `cli/cert.py` as a sibling of `cli/scan.py`. Zero churn to other files. **Sequencing: after this ADR's PR.**

If this ADR's PR doesn't land before MVP 0.2 starts, every later subcommand re-litigates "which `cli.py` section does this go into" instead of "which file under `cli/`."

## Decision rules

- **No behavior change.** This is a structural refactor. Every existing test must pass without modification. If a test imports a name that moves to a private submodule (`_options`, `_branding`), the test imports update; the assertion does not.
- **No public API change.** `pyproject.toml`'s `[project.scripts]` entry-point `qureddy = "qureddy.cli:main"` continues to work. `from qureddy.cli import app` continues to work for tests using `CliRunner`.
- **No new dependencies.** Pure source-tree restructure.
- **Single PR per ADR convention.** This ADR's tracking issue is #60. The implementation lands as one PR. Hitchhiking unrelated work is forbidden per coding-rules Rule 1.3.
- **The `_fail` helper is in scope** of this ADR's PR (it's mechanically extractable during the move). Other refactors (e.g. #76 `make_id` helper) are NOT in scope — those are separate one-file PRs.

## Acceptance criteria

- [ ] `src/qureddy/cli.py` no longer exists; `src/qureddy/cli/` package exists with the seven files above.
- [ ] Every existing test passes without modification (test files may need import-path updates only — not assertion changes).
- [ ] `pyproject.toml` `[project.scripts]` `qureddy` entry-point still resolves.
- [ ] `qureddy --help`, `qureddy scan --help`, `qureddy scan tls --help` produce identical output to pre-refactor.
- [ ] `qureddy scan tls www.google.com` produces identical output to pre-refactor (verdict, JSON schema, exit code).
- [ ] No file in `src/qureddy/cli/` exceeds 200 lines.
- [ ] No function in any new file exceeds 50 lines.
- [ ] `just gates` passes (lint, format-check, mypy --strict, test, bandit, pip-audit, deptry, reuse-lint).
- [ ] `python-oss-crypto-reviewer` skill review on the PR diff returns APPROVE.
- [ ] `validate-fix` skill validation against #60 returns `validated`.

## Out-of-scope (file separately)

- **#76 `make_id()` helper** — separate one-file PR, doesn't ride on the cli.py split.
- **#77 `_FindingFields` mixin** — separate one-file PR.
- **#79 `_commands_panel` split** — separate one-file PR; touches `output/console.py`, not `cli.py`.
- **#46 retry constants dedup** — separate two-line PR.
- **CLI design rules doc** (#78) — should land first if possible (gives the refactor a citable standard) but is not blocking.

## References

- `docs/contributors/coding-rules.md` Rule 2.1 (file size hard ceiling), Rule 2.2 (function size hard ceiling), Rule 1.3 (one thing per PR)
- ADR 0003 — CLI `--help` rewrite per best-practice patterns (work that will land in the new package)
- ADR 0004 — Multi-scanner architecture for MVP 0.2 (motivates the per-subcommand-file shape)
- Issue #60 — implementation tracking
- Issues #41-#45 — ADR 0003 follow-ups that benefit from this refactor landing first
