<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# CLI Design Rules — BreachSAFE QuReddy

These are the conventions every QuReddy CLI surface follows: root command, every subcommand, every flag, every exit code. They apply to humans, AI agents, and reviewers. They are the operational form of the canonical CLI design literature ([clig.dev](https://clig.dev), [POSIX `getopt(3)`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getopt.html), [GNU Coding Standards §4.7](https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html), [no-color.org](https://no-color.org)).

Where a rule below carries no citation, it is a **QuReddy-specific decision** with the rationale stated inline.

This document covers *how the CLI behaves*. It does not cover *what the CLI scans* (that is the scanner code under `src/qureddy/scanners/`) or *what the help text says* (that is per-PR copywriting). Rule changes here go through ADR + reviewer pass per [`review-process.md`](review-process.md).

QuReddy's CLI is **Typer + Rich + structlog** running on top of **Click 8**. Rules below cite the Typer/Click idioms they translate to. When in doubt, the rule wins; the implementation follows it.

> **Tracker provenance.** Links to `paul007ex/qureddy` in this document are
> historical implementation records in the private staging tracker. They are
> context, not current public authority. The shipped contract is defined by
> the [CLI reference](../reference/cli.md), the
> [exit-code reference](../reference/exit-codes.md), current source and tests,
> and the canonical public
> [release documentation issue](https://github.com/breachsafe/qureddy/issues/35).

> **Why this matters.** The shipped `scan tls` and `scan ssh` commands share one command-group convention, output contract, and exit-code surface. New scanner work must follow the same reviewable rules.

---

## Section 1 — Universal CLI Conventions

These rules apply to every Unix-style CLI. They are **not** QuReddy-specific.

**Rule 1.1 — `--help` always exits 0 and writes to stdout.**
A user running `qureddy --help` is asking for information; that is success. Help is grep-able and pipe-able. Citation: [clig.dev "Help"](https://clig.dev/#help).

**Rule 1.2 — `--version` is a required surface, exits 0, writes to stdout.**
Both `--version` and the short form `-V` (capital, per GNU §4.7) print the version banner and nothing else. The banner must be machine-parseable: a single line, predictable shape, version string at a fixed offset. Implementation reference: PR [#55](https://github.com/paul007ex/qureddy/pull/55).

**Rule 1.3 — Three-tier help structure.**
`qureddy --help` is the root help: subcommand list, global flags, environment variables, exit-code summary. `qureddy scan tls --help` and `qureddy scan ssh --help` are subcommand help: every flag for that command, examples, and exit codes that command can emit. Citation: [clig.dev "Tiered help"](https://clig.dev/#help).

**Rule 1.4 — Subcommand naming is verb-noun.**
`scan tls`, `scan ssh`. The verb is constant (`scan`); the noun identifies the endpoint protocol. Citation: [clig.dev "Subcommands"](https://clig.dev/#subcommands).

**Rule 1.5 — Long flags spell out; short flags are mnemonic.**
`--verbose`/`-v`, `--quiet`/`-q`, `--version`/`-V`, `--format`/`-f`. Long flags are self-documenting at the shell prompt; short flags exist for interactive use only. Every short flag has a long form. Not every long flag has a short form (the bar is high — short letters run out). Citation: [POSIX `getopt(3)`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getopt.html), [GNU §4.7](https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html).

**Rule 1.6 — Boolean flags are on/off only; no `--quiet=true`.**
Presence asserts; absence denies. `--quiet` enables quiet mode; there is no `--quiet=false` or `--no-quiet`. The `--no-<flag>` form is reserved for explicitly negating a default-on behavior, and QuReddy currently has none. Citation: [POSIX `getopt(3)`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getopt.html).

**Rule 1.7 — Required = positional. Optional config = flag.**
The target to scan is positional (`qureddy scan tls TARGET`); the SNI override is a flag (`--sni HOST`). Positional args are the verb's required object; flags configure how the verb runs. A required flag is a smell — promote it to positional or rethink the surface. Citation: [clig.dev "Arguments and flags"](https://clig.dev/#arguments-and-flags).

**Rule 1.8 — Defaults documented in help; no hidden behavior.**
Every flag's `help=` string names the default in `[default: X]` shape. Typer renders this automatically when defaults are set on the parameter. Hidden defaults (set in code but not in help text) are a re-review trigger.

**Rule 1.9 — Errors → stderr, results → stdout.**
The contract that makes `qureddy scan tls TARGET --format json | jq` work. Logs go to stderr. Scan output goes to stdout. Crashes go to stderr. **This rule is the most-broken in QuReddy's history** — see issues [#15](https://github.com/paul007ex/qureddy/issues/15), [#22](https://github.com/paul007ex/qureddy/issues/22), [#24](https://github.com/paul007ex/qureddy/issues/24) for the canonical cautionary tale where a `print()` mid-scan and a `CliRunner` fixture conspired to leak logs into stdout. Citation: [clig.dev "Output"](https://clig.dev/#output), POSIX file descriptor convention.

**Rule 1.10 — `NO_COLOR` (env var) preferred over `--no-color` (flag).**
A contributor wanting colorless output sets `NO_COLOR=1` in their environment, not `--no-color` per-invocation. The env-var form composes (CI runners set it once); the flag form forces every invocation site to decide. QuReddy has no `--no-color` flag and should not gain one. Citation: [no-color.org](https://no-color.org).

**Rule 1.11 — Exit codes are a public contract; document deviation from `sysexits.h`.**
QuReddy uses **0 / 2 / 3 / 4 / 70**, NOT BSD `sysexits.h`. The full surface lives in [`docs/reference/exit-codes.md`](../reference/exit-codes.md). When a code is added, maintainer sign-off and a documented compatibility decision are required; see [#12](https://github.com/paul007ex/qureddy/issues/12) for the addition of code 70. Reviewing this rule's violation is one of the harder catches because exit-code drift is invisible until a CI script `if $? -eq 2` script breaks. The PR template's exit-code checklist exists for exactly this reason.

**Rule 1.12 — Helpful errors on common typos.**
When the user types `--v`, `--vv`, `--verbos`, or applies `--version` to a subcommand instead of root, the error message names the right form. Click's default "no such option" message is too cryptic. PR [#80](https://github.com/paul007ex/qureddy/pull/80) and PR [#65](https://github.com/paul007ex/qureddy/pull/65) are the implementations.

---

## Section 2 — Python / Typer-Specific Conventions

These rules are how Section 1 translates into the QuReddy implementation.

**Rule 2.1 — Use `Annotated[type, typer.Option(...)]`, not bare defaults.**

```python
# YES — the type and the option spec are separable, the function signature is reusable
def scan_tls(
    target: Annotated[str, typer.Argument(help="Target host or host:port")],
    sni: Annotated[str | None, typer.Option(help="SNI override")] = None,
) -> None: ...

# NO — type info is buried; mypy and IDEs see less; tests cannot import the option type
def scan_tls(
    target: str = typer.Argument(...),
    sni: str = typer.Option(None),
) -> None: ...
```

The `Annotated` form is what Typer's docs recommend for >0.9. It separates type from option metadata and lets us extract repeated option shapes into module-level type aliases (Rule 2.2).

**Rule 2.2 — Module-level type aliases for repeated option shapes.**
When the same `Annotated[type, typer.Option(...)]` appears in three or more commands, extract it. `VersionOpt`, `SniOpt`, `FormatOpt` are the existing examples. New scanners should add their own aliases as new commands grow. The aliases live near the top of `cli.py` (or its split-out package post-#60); the type expression is the documentation.

**Rule 2.3 — Range constraints on the type, not in the body.**
`Annotated[int, typer.Option(min=0, max=10, clamp=False)]` for a flag that takes a bounded integer. Click validates at usage-error time and exits 4. Validating in the function body changes the usage-error contract.

**Rule 2.4 — Use `typer.Exit(code=N)` from inside commands; not `sys.exit(N)`.**
Typer needs to unwind cleanly so resource cleanup runs (Rich's progress bars, structlog handlers, async loops). `sys.exit` raises `SystemExit` which Typer treats as an unexpected crash and may report internal-error exit code 70 instead of the intended target-failure code 2.

**Rule 2.5 — Typer's `--help` is auto-generated; expand `help=` strings, don't subclass.**
Long, multi-paragraph help with `EXAMPLES` and `EXIT CODES` sections lives in Typer's `epilog=` parameter using the Click `\b` form-feed convention to preserve literal newlines (Rich's default is to collapse single newlines). Do not subclass `typer.Typer` to override help rendering; that breaks Typer's update path. Implementation reference: PR [#73](https://github.com/paul007ex/qureddy/pull/73) (closes [#71](https://github.com/paul007ex/qureddy/issues/71)).

**Rule 2.6 — Validation at usage-error time exits 4, not 2.**
The `cli:main` wrapper translates Click's `UsageError` to exit code 4. Pointing the install-time entrypoint at `cli:app` directly would let Click default to exit 2 — colliding with target-scan-failure. The wrapper is non-negotiable; see `pyproject.toml [project.scripts]` and PR [#51](https://github.com/paul007ex/qureddy/pull/51) for the surrounding history.

**Rule 2.7 — No stack traces in CLI mode unless the user asked.**
A user running `qureddy scan tls badtarget.example` gets a one-line error and exit 2, not a 40-line Python traceback. Tracebacks are a developer signal; the CLI is for operators. The escape hatch is the `--trace` flag (verbosity ladder; implementation pending).

**Rule 2.8 — Logging through `structlog`, never `print()` or `typer.echo`.**
`print()` writes to stdout, which violates Rule 1.9 for any non-result output. `typer.echo` is `print()` in a wrapper. `structlog` writes to stderr (Rule 1.9 ✓), supports key/value structure (machine-parseable per Rule 6 of [`coding-rules.md`](coding-rules.md)), and respects `NO_COLOR` (Rule 1.10). The only place stdout gets written from is the output renderer (`src/qureddy/output/`).

---

## Section 3 — QuReddy-Specific Decisions

Decisions that diverge from defaults or shared conventions, with rationale.

**Rule 3.1 — Custom exit codes 0 / 2 / 3 / 4 / 70, not `sysexits.h`.**
`sysexits.h` defines codes 64–78 with semantics like `EX_USAGE=64`, `EX_DATAERR=65`. QuReddy uses **0 (success), 2 (target scan failed), 3 (local dependency missing/broken), 4 (usage error), 70 (internal qureddy bug)**. Decision rationale: CI scripts in the wild assume `0 = good, !0 = bad` and frequently `if $? -eq 2; then alert`. Surfacing five codes from the small end of the integer space makes the contract memorable; surfacing five codes from `sysexits.h`'s middle range (64, 65, 70, 78) loses the distinction between "target failed" and "dataerr." Code 70 reuses the BSD `EX_SOFTWARE` value because internal bugs *are* software errors and CI scripts that already know `sysexits.h` will recognize it. Issue [#12](https://github.com/paul007ex/qureddy/issues/12) records the formal decision.

**Rule 3.2 — Adding a new exit code is a contract change.**
The exit-code surface is a public contract. New codes need (a) a documented use case where existing codes are wrong, (b) an ADR, (c) reference doc update, (d) PR-template checkbox. Issue [#12](https://github.com/paul007ex/qureddy/issues/12) is the canonical add-a-code issue; reviewers should treat any new code addition the same way.

**Rule 3.3 — The stdout/stderr contract is the most important rule.**
Rule 1.9 is universal; this is the QuReddy-specific reinforcement: **every PR that touches the output path must include a test that asserts which stream the output went to.** Issues [#15](https://github.com/paul007ex/qureddy/issues/15), [#22](https://github.com/paul007ex/qureddy/issues/22), [#24](https://github.com/paul007ex/qureddy/issues/24) are the cautionary tale where the contract drifted under `CliRunner(mix_stderr=True)` defaults and three tests passed against a wrong assumption. The fix in [#33](https://github.com/paul007ex/qureddy/pull/33) split stdout/stderr capture explicitly. New CLI tests must do the same.

**Rule 3.4 — `--no-color` is not a flag QuReddy supports.**
`NO_COLOR=1` is the canonical disable per [no-color.org](https://no-color.org) and Rule 1.10. Adding a `--no-color` flag would (a) duplicate the env-var convention, (b) force every invocation site to decide, (c) require sub-flag-level documentation explaining when each form takes precedence. The decision is to support exactly one form and document it. If a future contributor proposes `--no-color`, the answer is "use `NO_COLOR=1`."

**Rule 3.5 — Subcommand-level `--version` rejects with a helpful pointer.**
Click's default for `qureddy scan tls --version` is "no such option: --version." That is true (the option is on the root, not the subcommand) but unhelpful. PR [#65](https://github.com/paul007ex/qureddy/pull/65) detects the misplacement and prints "did you mean `qureddy --version`?" before exiting 4.

**Rule 3.6 — Verbosity is a counter, stacked POSIX-style.**
`-v` (INFO), `-vv` (DEBUG), `-vvv` (DEBUG + traceability panel). The `--verbose` long form takes no count argument. Typo handling for `--v`, `--vv`, `--vvv`, `--verbos` is implemented per Rule 1.12 in PR [#80](https://github.com/paul007ex/qureddy/pull/80) (closes [#74](https://github.com/paul007ex/qureddy/issues/74)).

---

## Section 4 — What This Document Does NOT Cover

- **Help text wording.** Per-PR copywriting; not a rule.
- **Specific scanner behavior.** Owned by the active implementation skill in `.agents/skills/`.
- **Exit-code propagation bugs.** Tracked in issues, not rules.
- **Input validation gaps.** Tracked in issues (e.g. [#13](https://github.com/paul007ex/qureddy/issues/13)), not rules.
- **`--help` snapshot tests.** Tracked in [#88](https://github.com/paul007ex/qureddy/issues/88).
- **Exit-code contract tests.** Tracked in [#89](https://github.com/paul007ex/qureddy/issues/89).

---

## References

- [clig.dev — Command Line Interface Guidelines](https://clig.dev) — the modern canonical reference.
- [POSIX `getopt(3)`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getopt.html) — flag parsing baseline.
- [GNU Coding Standards §4.7](https://www.gnu.org/prep/standards/html_node/Command_002dLine-Interfaces.html) — long-flag spelling and `-V` for `--version`.
- [no-color.org](https://no-color.org) — `NO_COLOR` env-var convention.
- [BSD `sysexits.h`](https://man.freebsd.org/cgi/man.cgi?query=sysexits) — the exit-code convention QuReddy diverges from (Rule 3.1).
- [`coding-rules.md`](coding-rules.md) — Python authoring rules. CLI design is a layer above; coding-rules covers the language.
- [`review-process.md`](review-process.md) — how a PR that changes CLI surface gets reviewed.
- [`oss-standards.md`](oss-standards.md) — release, license, and community conventions. CLI surface is part of the OSS contract.
