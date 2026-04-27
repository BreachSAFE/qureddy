# ADR 0003 — CLI `--help` rewrite per best-practice patterns

**Status:** Implementing — slices 1–3 of 4 shipped (#41); slice 4 in progress
**Date:** 2026-04-26
**Deciders:** Paul Volosen, project lead
**Consulted:** Claude (review)
**Informed:** Codex
**Supersedes:** none
**Superseded by:** none

---

## Context

QuReddy is a CLI-first tool. Users discover, evaluate, and operate it primarily through `qureddy --help` and `qureddy scan tls --help`. The current help output is the Typer default: a Rich-formatted option table per command, no examples, no exit code reference, no environment variable documentation, no quick-start.

Three audiences hit `--help` first:

| Audience | Their question | What current help gives them |
|---|---|---|
| Customer doing first eval | "What does this thing do?" | A flag table, no examples, no synopsis. They bounce. |
| Co-founder during demo | "What can I claim it does? Show me the surface." | Same flag table. No exit codes, no verdicts list. |
| Operator integrating to CI | "Every flag, every default, every value." | This is the only audience the current help serves. |
| Expert running a one-off scan | "Get out of my way." | Default `--help` is too long for them. |

The pattern modern CLIs use to serve all four cleanly is **tiered help** combined with **mandatory `EXAMPLES` blocks**, with reference to four named patterns from the OSS canon (POSIX synopsis, three-tier help, EXAMPLES section, framework epilog).

This ADR locks the design before implementation so reviewers and future contributors apply the same conventions without re-litigating them per PR.

## Decision

**Adopt a four-pattern help-output design and ship it as a follow-up to the docs reorg PR.**

### Pattern 1 — Three-tier help

| Tier | Invocation | Audience | Length |
|---|---|---|---|
| **1 short** | `qureddy -h`, `qureddy <cmd> -h` | "I forgot the syntax" | 5–10 lines |
| **1 overview** | `qureddy` (no args), `qureddy --help` | "What is this?" | 25–30 lines |
| **2 full options** | `qureddy <cmd> --help` | "Which flag do I want?" | option table + EXAMPLES + EXIT CODES + ENV |
| **3 manual** | `qureddy <cmd> --help-all` | "Explain everything" | long-form prose, all options with rationale |

Tier 1 short is the synopsis: usage line plus one-sentence description. Tier 1 overview answers "what does this do" with quick start examples. Tier 2 is the current Typer table, augmented. Tier 3 is the in-terminal manual.

### Pattern 2 — POSIX synopsis line on every command

Every help screen starts with the standard usage line:

```
qureddy scan tls [OPTIONS] TARGET
qureddy scan tls [-q | -v...] [--format=FMT] [--sni=HOST] TARGET
```

Notation per [Open Group Utility Conventions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html):

- `[brackets]` = optional
- `arg...` = repeatable
- `a | b` = mutually exclusive
- `UPPERCASE` = placeholder
- `lowercase` = literal

A fluent reader scans the synopsis first. If they already know the shape, they don't need the rest.

### Pattern 3 — Mandatory `EXAMPLES` block

Every command before merge must have at least 3 runnable examples in an `EXAMPLES` section. Examples are ordered common → edge case. Each is a complete, runnable command — never a fragment.

Reference exemplar: `gh pr create --help`.

This is enforceable in code review. Adding a command without examples blocks merge.

### Pattern 4 — Use Typer's `epilog=` parameter for non-option content

The option table answers "what does each flag do." The epilog answers "what would you actually type." Move into epilogs:

- `EXAMPLES`
- `EXIT CODES`
- `ENVIRONMENT`
- `VERDICTS` (the at-a-glance signal mapping)
- "See also" links (tutorial, how-to, online docs)

### Conventions adopted alongside the patterns

These aren't help-output strictly but they make the CLI feel professional:

| Convention | Why |
|---|---|
| `-h` and `--help` always work, every subcommand | Universal escape hatch |
| Help on stdout, errors on stderr | `cmd --help \| less` works without `2>&1` |
| Exit 0 on `--help` | Help is success, not error (Typer/Click default — verify) |
| `qureddy` (no args) prints Tier-1 overview | No-args → "what is this" not "missing command" error |
| `qureddy help <subcommand>` aliases `qureddy <subcommand> --help` | Discoverability win, `git help`-style |
| Honor `NO_COLOR` in help output | Already done in Rich renderer; extend |
| **At v1.0**: man pages auto-generated | `click-man` from the same metadata |
| **At v1.0**: shell completions shipped | `typer --install-completion` |

## Consequences

### What changes

- A custom Tier-1 help callback replaces Typer's default for `qureddy --help` and bare `qureddy`. About 30 lines.
- Every Typer command gains an `epilog=` containing `EXAMPLES`, `EXIT CODES`, `ENVIRONMENT`. About 10–20 lines per command.
- A new `--help-all` flag at the subcommand level prints the long-form manual. About 100–200 lines per subcommand.
- A new `qureddy help <sub>` subcommand aliases `--help` for discoverability. About 15 lines.
- Code review checklist gains: "every new subcommand has ≥3 EXAMPLES." Goes in `.github/PULL_REQUEST_TEMPLATE.md` and `docs/contributors/coding-rules.md`.

### What does not change

- Existing flags and exit codes — this is purely about help-text presentation
- The JSON schema, the `ScanResult` model surface, the locked enum values
- The `--format`, `--openssl`, `--sni`, `--retry-on`, `--retries`, `--retry-delay`, `--timeout`, `-v`, `--json-logs`, `--quiet` options
- The Typer + Click + Rich dependency stack

### What gets harder

- Every new subcommand requires editorial work to write good examples. This is the *intended* cost — examples are how users learn the tool.
- The custom Tier-1 callback bypasses some Typer auto-formatting; we own its layout going forward.

## Alternatives considered

### Alternative 1 — Keep the Typer default, add only `EXAMPLES` blocks

Lower cost. Adds the highest-leverage piece (examples) without the Tier-1 / Tier-3 work.

**Rejected** because it doesn't fix the no-args behavior or the "what is this" gap. The Tier-1 overview is the screen a customer or co-founder sees first; leaving it as a flag table is a missed opportunity that compounds with every install.

### Alternative 2 — Single big `--help` (man-page style)

Linux `man` convention: one long help document covering everything.

**Rejected** because it shorts the casual user. Most modern CLIs (`git`, `cargo`, `gh`, `kubectl`) tier specifically to avoid drowning the 5-second reader.

### Alternative 3 — `qureddy guide` as a separate subcommand instead of `--help-all` flag

Instead of `qureddy scan tls --help-all`, add `qureddy guide [topic]`.

**Rejected** because `--help-all` is the convention `helm` and `kubectl` use, and convention-following helps users transfer mental models from other tools. Reconsider if a "topic" structure emerges (multiple guides, by feature) — at MVP 0.1 there's only one command.

### Alternative 4 — Defer to man pages at v1.0

Skip `--help-all`; rely on man pages once they ship.

**Rejected** because man pages are an OS-specific thing (no man pages on Windows, weak on macOS without `mandoc`). In-terminal `--help-all` works everywhere `qureddy` runs. Man pages are an *additional* surface at v1.0, not a replacement.

### Alternative 5 — Don't tier; let `--help` be 200 lines

The `aws` CLI does this. Whole world of options dumped on stdout.

**Rejected** because the AWS CLI gets away with it through `aws help` opening a pager. We don't have a pager dependency and don't want one. Tier-3 in our model is the equivalent without forcing `less`.

## Implementation order

This ADR lands in the `docs/diataxis-reorg` PR with `Status: Proposed`. After that PR merges:

1. **Open a GitHub issue** using `.github/ISSUE_TEMPLATE/feature_request.md`. Title: `feat(cli): full --help rewrite per ADR 0003`. Body links to this ADR.
2. **New branch** `feat/cli-help-rewrite` off main.
3. **Implement Pattern 1 (three-tier)** first — custom callback, `--help-all` flag.
4. **Implement Pattern 4 (epilogs)** for `scan tls` — EXAMPLES, EXIT CODES, ENVIRONMENT, VERDICTS.
5. **Implement no-args behavior + `qureddy help <sub>` alias.**
6. **Update `docs/contributors/coding-rules.md`** with the EXAMPLES-mandatory rule.
7. **Update `.github/PULL_REQUEST_TEMPLATE.md`** with the EXAMPLES checklist item.
8. **Update this ADR** Status: Proposed → Accepted in the same PR.
9. **PR description** links back to the GitHub issue and to this ADR.

## Acceptance criteria

For implementation to be considered complete:

- [ ] `qureddy` (no args) prints Tier-1 overview, exits 0
- [ ] `qureddy --help` and `qureddy -h` both work, exit 0, output to stdout
- [ ] `qureddy scan tls --help` shows option table + EXAMPLES + EXIT CODES + ENVIRONMENT (via epilog)
- [ ] `qureddy scan tls --help-all` shows long-form manual with prose per option
- [ ] `qureddy help scan tls` works as alias for `qureddy scan tls --help`
- [ ] `qureddy --version` works as standalone, not buried in `--help`
- [ ] Honors `NO_COLOR` in all help output
- [ ] All Tier 1 quality gates pass (ruff, mypy, pytest, coverage ≥ 80%)
- [ ] At least one CLI test verifies each tier (1, 2, 3) produces non-empty output
- [ ] Code review checklist item added: "EXAMPLES block present on new subcommands"

## Related

- [ADR 0001 — `--trace` flag and verbosity refactor](0001-trace-and-verbosity.md) — depends on the verbosity ladder this ADR formalizes
- [ADR 0002 — Diátaxis documentation standard](0002-diataxis-documentation-standard.md) — the help-output tiers map to Diátaxis quadrants (Tier 1 = synopsis-as-tutorial, Tier 2 = reference, Tier 3 = explanation-flavored reference)
- [`docs/reference/cli.md`](../../reference/cli.md) — the canonical option list this work synchronizes with

## References

- [Open Group Utility Conventions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html) — POSIX synopsis notation
- [`gh` CLI source](https://github.com/cli/cli) — `EXAMPLES` blocks exemplar
- [`cargo` source](https://github.com/rust-lang/cargo) — three-tier help + auto-generated man pages
- [`kubectl` source](https://github.com/kubernetes/kubectl) — `--help-all` flag exemplar
