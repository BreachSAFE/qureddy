<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR 0005 — Splitting oversized files into purpose-organized packages

**Status:** Proposed
**Date:** 2026-04-27
**Deciders:** Paul Volosen, project lead
**Consulted:** Claude (drafting), Codex (architect / arbiter)
**Informed:** MVP 0.2+ contributors
**Supersedes:** none
**Superseded by:** none
**Tracking issues:** [#60](https://github.com/paul007ex/qureddy/issues/60) (cli.py), [#82](https://github.com/paul007ex/qureddy/issues/82) (openssl_probe.py), [#69](https://github.com/paul007ex/qureddy/issues/69) (tests/test_cli.py)
**Related:** [ADR 0003](0003-cli-help-rewrite.md), [ADR 0004](0004-multi-scanner-architecture.md), [#41](https://github.com/paul007ex/qureddy/issues/41), [#42](https://github.com/paul007ex/qureddy/issues/42)-[#45](https://github.com/paul007ex/qureddy/issues/45), [#79](https://github.com/paul007ex/qureddy/issues/79)

---

## Context

Three production files have crossed or are within 30 LOC of `coding-rules.md` Rule 2.1's 400-line hard file ceiling, and one test file is nearly double the ceiling:

| File | LOC | Status | Tracking issue |
|---|---|---|---|
| `src/qureddy/cli.py` | **429** | Over by 29 | [#60](https://github.com/paul007ex/qureddy/issues/60) |
| `src/qureddy/scanners/tls/openssl_probe.py` | **424** | Over by 24 | [#82](https://github.com/paul007ex/qureddy/issues/82) |
| `src/qureddy/output/console.py` | 370 | 30 LOC under (canary zone) | [#79](https://github.com/paul007ex/qureddy/issues/79) (function-level split) |
| `tests/test_cli.py` | **774** | Almost double the ceiling | [#69](https://github.com/paul007ex/qureddy/issues/69) |

Three of these breaches happened in the last week of MVP 0.1 work. None of them are new features — they are the natural cost of doing bug fixes correctly (PR #81's `LOCAL_OPENSSL_BROKEN` category, ADR 0003's help-rewrite work, etc.). The size pressure is the consequence of doing the work right; the structural split is the standard response.

The decision rule needed by the next contributor is **not** "is this specific file too big?" — that's already answered by `wc -l` and the new `file-size-gate.yml` workflow that just landed on `main`. The decision rule needed is:

> When a file exceeds Rule 2.1, what's the canonical way to split it?

Without a written rule, every file-splitting PR re-litigates "should this be a package?", "by purpose or by feature?", "what about backward compatibility?". This ADR answers those questions once.

## Decision

**When a file exceeds Rule 2.1's 400-line hard ceiling, split it into a purpose-organized package, not via aggressive helper extraction in the same module.**

The package replaces the single-file module on disk and re-exports the public surface for backward compatibility. The split is by **purpose** (data, behavior, glue), not by **feature** (subcommand, probe type, output format). Feature fan-out happens at the next milestone when the second concrete instance of the feature exists.

### Decision rules (apply to every Rule 2.1 split going forward)

**Rule A — Package replaces module.**
The single-file module becomes a package directory of the same name. `src/qureddy/foo.py` → `src/qureddy/foo/`. `__init__.py` re-exports the public names so `from qureddy.foo import bar` continues to resolve.

**Rule B — Split by purpose, not by feature.**
A `cli/` package is split into `_branding`, `_options`, `_help`, `_errors`, `main`, `scan` — **not** into `scan_tls.py`, `scan_cert.py`, `scan_ssh.py` per subcommand. Subcommand fan-out happens when the **second** concrete subcommand lands, not at the split itself. The same applies to `openssl_probe/`: split into `capability`, `probe`, `_results`, `_logging` — **not** into `hybrid_probe.py`, `classical_probe.py` per group.

**Rule C — Underscore prefix on shared infrastructure.**
Modules that hold private helpers (`_branding`, `_options`, `_help`, `_errors`, `_results`, `_logging`) are private to the package. `__init__.py` does not re-export them. Tests that need to reach in import via the parent package; nobody else should.

**Rule D — Subcommands / commands / public entry points at top level of the package.**
`cli/main.py`, `cli/scan.py`, `cli/cert.py` (future). Not `cli/scan/tls.py`. Each public-shaped file is a sibling at the package root.

**Rule E — No file in the new package exceeds 200 LOC.**
The 200 LOC target is *half* the file-size ceiling — gives every file room to grow before the next split. If a single concern doesn't fit in 200 LOC, that's a signal to split that concern further, not a license to make one file bigger than its siblings.

**Rule F — No new dependencies.**
The split is a structural refactor. Every file existed in the source tree before; the package version is the same code redistributed. If you find yourself adding a dependency to make the split work, the design is wrong — fix the design, not the dependency list.

**Rule G — No behavior change.**
Every existing test passes without modification. Test files may need import-path updates only — never assertion changes. If an assertion breaks, the split changed observable behavior and the PR is rejected.

**Rule H — One file per ADR commitment.**
This ADR commits to splitting two files (`cli.py`, `openssl_probe.py`) as separate PRs. It does **not** commit to splitting `tests/test_cli.py` (#69) — that's a test-organization concern handled by a separate ADR or PR. Future Rule 2.1 breaches in production code reference this ADR and follow Rules A-G; future Rule 2.1 breaches in test code may need their own decision because the constraints are different (test files are organized by behavior-under-test, not by purpose).

### Worked example 1: `src/qureddy/cli.py` (#60)

`cli.py` is 429 LOC and contains nine distinct concerns. After the split:

```
src/qureddy/cli/
├── __init__.py        # ~10 LOC — re-export `app`, `main` for entry-point compatibility
├── _branding.py       # ~40 LOC — PROJECT_NAME, PROJECT_URL, SOURCE_URL, LICENSE_NAME,
│                      #          VERSION_BANNER, _version_callback (ADR 0003 §"Branding")
├── _options.py        # ~80 LOC — Annotated option aliases (TargetArg, SniOpt, OpenSSLOpt,
│                      #          FormatOpt, TimeoutOpt, RetryOnOpt, RetriesOpt,
│                      #          RetryDelayOpt, VerboseOpt, JsonLogsOpt, QuietOpt)
├── _help.py           # ~80 LOC — epilog blocks, examples, expanded option help text
│                      #          per ADR 0003 §"Examples block" and §"Epilog"
├── _errors.py         # ~60 LOC — _fail(msg, code) helper consolidating the three
│                      #          try/except/typer.Exit ladders + Click error
│                      #          classifier helpers (_is_version_misplacement,
│                      #          _is_verbosity_dash_confusion)
├── main.py            # ~150 LOC — app = typer.Typer(...), scan_app, _root callback,
│                      #          main() entry-point wrapper. Glue only — no command logic.
└── scan.py            # ~150 LOC — @scan_app.command("tls") body and orchestration:
                       #          _execute_scan, _parse_retry_args, _parse_cli_target,
                       #          _render. Becomes a sibling of cli/cert.py at MVP 0.2.
```

**Sub-task in scope of #60's PR — extract `_fail(msg, code)` helper.**
Three near-identical `try/except/typer.Exit` blocks at `cli.py:275-277`, `285-287`, `313-316` collapse into:

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

Saves ~6 LOC, gives a single boundary for future cross-cutting concerns (JSON-mode error formatting, structured-log error events).

### Worked example 2: `src/qureddy/scanners/tls/openssl_probe.py` (#82)

`openssl_probe.py` is 424 LOC and contains six distinct concerns. After the split:

```
src/qureddy/scanners/tls/openssl_probe/
├── __init__.py        # ~25 LOC — re-export public names so existing imports
│                      #          continue to work:
│                      #            from qureddy.scanners.tls.openssl_probe import (
│                      #                resolve_openssl_path, probe_capability,
│                      #                raise_if_unusable, run_hybrid_probe,
│                      #                run_classical_probe, DEFAULT_TIMEOUT_SECONDS,
│                      #                MIN_OPENSSL_VERSION, HYBRID_GROUP,
│                      #                CLASSICAL_GROUP, EXCERPT_LIMIT,
│                      #                _classify_failure,  # legacy test import
│                      #            )
├── _constants.py      # ~15 LOC — DEFAULT_TIMEOUT_SECONDS, MIN_OPENSSL_VERSION,
│                      #          HYBRID_GROUP, CLASSICAL_GROUP, EXCERPT_LIMIT,
│                      #          OPENSSL_VERSION_PATTERN, ENV_OVERRIDE
├── capability.py      # ~150 LOC — resolve_openssl_path, probe_capability,
│                      #          raise_if_unusable, _run_openssl, _extract_version,
│                      #          _parse_group_list. The "is this OpenSSL usable?"
│                      #          subprocess path. Owns the subprocess for non-probe
│                      #          calls (`openssl version`, `openssl list`).
├── probe.py           # ~100 LOC — run_hybrid_probe, run_classical_probe,
│                      #          _run_probe, _build_probe_args. The "scan this
│                      #          target" subprocess path. Owns the subprocess for
│                      #          `openssl s_client`.
├── _results.py        # ~80 LOC — _build_probe_result, _probe_result_from_timeout,
│                      #          _decode_partial. Pure ProbeResult construction
│                      #          (no subprocess; consumed by `probe.py`).
└── _logging.py        # ~30 LOC — _log_subprocess_start, _log_subprocess_complete.
                       #          Subprocess-specific structlog event helpers.
```

**Each new file ≤ 150 LOC**, well under the 200 LOC Rule E target. The split surfaces the actual structure: capability check (one subprocess concern), probe execution (a different subprocess concern), result construction (pure data), logging (cross-cutting helper).

**Backward-compat note for tests.** The legacy `_classify_failure` re-export (line 354 of the current file: *"Re-exported so existing tests at tests/test_openssl_probe.py that import `_classify_failure` from this module keep working unchanged"*) moves to `__init__.py` and continues to work. No test imports change.

### Decision tree for future splits

When a file exceeds 400 LOC, walk this tree:

1. **Can the file be split by purpose into 4-7 files?** (Yes for `cli.py`, `openssl_probe.py`.) Apply Rules A-G.
2. **Is the file already at the lowest reasonable purpose-decomposition?** (e.g. `core/models.py` is 233 LOC of Pydantic models; splitting it by model is feature-decomposition, not purpose-decomposition.) Don't split — flag in `coding-rules.md` as an accepted exception. **Today: no production file is in this category.**
3. **Is the file actually a test file?** Tests are organized by behavior, not by purpose; their split rule is different. See Rule H. **Today: only `tests/test_cli.py` (774 LOC) hits this; tracked separately at #69.**

## Why this fits the project

**`coding-rules.md` Rule 2.1** explicitly anticipates the package-not-helper-extraction direction:

> *"The TLS scanner directory has separate files (`scanner.py`, `openssl_probe.py`, `parse.py`) instead of one `tls.py` for exactly this reason."*

The same logic applies recursively. When `openssl_probe.py` itself crosses the ceiling, the answer is to split *it* into a package, not to invent a deeper helper extraction. The recursion bottoms out when each file does one purpose.

**ADR 0004 (multi-scanner architecture)** introduces a `Scanner(Protocol)` and a per-scanner registry. Each scanner gets its own subcommand: `scan tls`, `scan cert`, `scan ssh`. The CLI and probe organization should mirror the scanner organization — one file per subcommand at the layer where features fan out, not at the helper layer.

**The recently-merged `.github/workflows/file-size-gate.yml`** enforces Rule 2.1 in CI. Without this ADR, the gate fails loudly but offers no guidance on what to do about it. With this ADR, the failure message can cite ADR 0005 as the playbook.

**ADR 0003 (CLI help rewrite)** has follow-up work in #41-#45 that will land in the new `cli/` package structure — those PRs will be cleaner if ADR 0005 lands first.

## Roadmap fit

- [x] **MVP 0.1 (now)** — both files are over the ceiling. Best window for the split because no MVP 0.2 work has touched either file yet.
- **#41 v1 remaining slices, #42-#45** (ADR 0003 follow-ups) — currently planned to land in `cli.py`; should land in the new package. **Sequencing: ADR 0005 implementation lands first.**
- **MVP 0.2 (`scan cert`)** — adds `src/qureddy/cli/cert.py` and `src/qureddy/scanners/cert/` (or similar). Zero churn to other files. **Sequencing: ADR 0005 implementation lands first.**
- **#79** (function-level split of `output/console.py:_commands_panel`) — separate one-file PR; `output/console.py` is at 370 LOC, not yet over the ceiling. **Sequencing: independent of ADR 0005.**
- **#69** (`tests/test_cli.py` 774 LOC) — separate decision per Rule H; this ADR explicitly defers test-file splitting.

## Decision rules — non-negotiables

- **No behavior change.** Every existing test passes without modification. (Rule G.)
- **No public API change.** `pyproject.toml`'s `[project.scripts]` entry-points continue to work. `from qureddy.cli import app`, `from qureddy.scanners.tls.openssl_probe import probe_capability`, etc. continue to resolve.
- **No new dependencies.** (Rule F.)
- **One ADR commitment per PR.** This ADR commits to two PRs (one per file). Hitchhiking unrelated work is forbidden per Rule 1.3.
- **The `_fail` helper is in scope** of the `cli.py` PR. (Mechanically extractable during the move.) Other refactors (#76 `make_id`, #77 `_FindingFields` mixin) are NOT in scope — those are separate one-file PRs.

## Acceptance criteria

### For #60 (cli.py PR)

- [ ] `src/qureddy/cli.py` no longer exists; `src/qureddy/cli/` package exists with the seven files in Worked Example 1.
- [ ] Every existing test passes without modification (test files may need import-path updates only).
- [ ] `pyproject.toml`'s `[project.scripts]` `qureddy = "qureddy.cli:main"` still resolves.
- [ ] `qureddy --help`, `qureddy scan --help`, `qureddy scan tls --help` produce identical output to pre-refactor.
- [ ] `qureddy scan tls www.google.com` produces identical output (verdict, JSON schema, exit code).
- [ ] No file in `src/qureddy/cli/` exceeds 200 LOC. (Rule E.)
- [ ] No function in any new file exceeds 50 LOC.
- [ ] `_fail(msg, code)` helper extracted; three try/except/typer.Exit ladders consolidated.
- [ ] `just gates` passes.
- [ ] `python-oss-crypto-reviewer` skill review on the PR diff returns APPROVE.
- [ ] `validate-fix` skill validation against #60 returns `validated`.

### For #82 (openssl_probe.py PR)

- [ ] `src/qureddy/scanners/tls/openssl_probe.py` no longer exists; `src/qureddy/scanners/tls/openssl_probe/` package exists with the six files in Worked Example 2.
- [ ] Every existing test passes without modification, including the legacy `_classify_failure` import path used by `tests/test_openssl_probe.py`.
- [ ] `from qureddy.scanners.tls.openssl_probe import probe_capability` (and the other public names listed in Worked Example 2's `__init__.py` comment) continue to resolve.
- [ ] `qureddy scan tls www.google.com` produces identical output to pre-refactor.
- [ ] No file in `src/qureddy/scanners/tls/openssl_probe/` exceeds 200 LOC. (Rule E.)
- [ ] No function in any new file exceeds 50 LOC.
- [ ] `just gates` passes.
- [ ] `python-oss-crypto-reviewer` skill review on the PR diff returns APPROVE.
- [ ] `validate-fix` skill validation against #82 returns `validated`.

## Out of scope (file separately if not already filed)

- **#76 `make_id()` helper** — separate one-file PR.
- **#77 `_FindingFields` mixin** — separate one-file PR.
- **#79 `_commands_panel` function-level split** — separate one-file PR; `output/console.py` is not over the ceiling.
- **#69 `tests/test_cli.py` split** — needs separate decision (Rule H); test-file splitting follows different criteria.
- **#46 retry constants dedup** — separate two-line PR; rides on #19's PR.
- **#56 file-size CI gate enforcement** — already partially landed via `file-size-gate.yml`; out of scope for this ADR's implementation.
- **#78 CLI design rules doc** — should land first if possible (gives the refactor a citable standard for help-text decisions in `cli/_help.py`) but not blocking.

## References

- `docs/contributors/coding-rules.md` Rule 2.1 (file size hard ceiling), Rule 2.2 (function size hard ceiling), Rule 1.3 (one thing per PR)
- `.github/workflows/file-size-gate.yml` — enforces Rule 2.1 in CI (recently merged)
- ADR 0003 — CLI `--help` rewrite (work that lands in the new `cli/` package)
- ADR 0004 — Multi-scanner architecture (motivates the per-subcommand-file shape in `cli/`)
- Issues [#60](https://github.com/paul007ex/qureddy/issues/60), [#82](https://github.com/paul007ex/qureddy/issues/82) — implementation tracking (one PR per file)
- Issues [#41](https://github.com/paul007ex/qureddy/issues/41), [#42](https://github.com/paul007ex/qureddy/issues/42), [#43](https://github.com/paul007ex/qureddy/issues/43), [#44](https://github.com/paul007ex/qureddy/issues/44), [#45](https://github.com/paul007ex/qureddy/issues/45) — ADR 0003 follow-ups that land in the new `cli/` package
- Issue [#79](https://github.com/paul007ex/qureddy/issues/79) — `output/console.py:_commands_panel` function split (independent)
- Issue [#69](https://github.com/paul007ex/qureddy/issues/69) — `tests/test_cli.py` size violation (deferred per Rule H)
