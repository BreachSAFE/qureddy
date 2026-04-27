<!-- SPDX-License-Identifier: Apache-2.0 -->
---
name: audit-docs
description: Detect drift between the documentation surface and the code/working tree. Read-only audit. Use when a PR touches CLI surfaces, exit-code contracts, JSON output schemas, or referenced ADRs; when a new skill or ADR is added; or as a periodic sweep. Companion to `audit-pr` (which audits code) and `run-quality-gates` (which runs tools). This skill audits *docs*: stale ADR statuses, dangling cross-references, drifted counts, runnable examples that no longer run, catalog entries that no longer match disk.
---

# Skill: audit-docs

Catches the drift that human review reliably misses: documentation that was correct when written but is stale now. Pairs with `audit-pr`. The two answer different questions:

- `audit-pr` — *Is the code in this diff ready to merge?*
- `audit-docs` — *Are the docs that talk about the code still telling the truth?*

This skill never edits docs or code. It produces a report; the human decides what to fix.

## When to invoke this skill

- A PR touches `src/qureddy/cli.py`, the JSON output surface, exit-code-emitting code, or any `docs/**`
- A new skill, ADR, or documented rule is added
- A milestone ships (#41, #82, etc. close)
- User asks "are the docs in sync with the code?"
- Periodic sweep (manual or scheduled)

If the diff is purely an internal refactor with no doc-relevant surface change, you can skip this skill.

## Procedure — four classes of check

Run each class in order. Capture findings in the report format at the bottom. Do not paraphrase: cite file path + line, what drifted, suggested fix.

### Class A — Runnable example execution

For every fenced code block in `README.md`, `docs/tutorials/`, `docs/how-to/`, `docs/reference/` tagged ` ```bash ` or ` ```console `:

1. Extract the command (first line, after `$` prompt if present).
2. If it's a `qureddy ...` invocation, run it in a sandbox (`uv run qureddy ...`) and capture exit code + stdout/stderr.
3. Compare against the documented output (the next ` ```text ` block) if present. Normalize timestamps, durations, version strings to placeholders before comparison.
4. Flag mismatches: missing subcommand, wrong exit code, output diverges past normalization tolerance.

**Carve-outs.** A code block tagged with the comment `<!-- audit-docs: skip-runnable, reason=v1.0-surface -->` (or `reason=mvp-0.2-surface`, etc.) is skipped. README's pre-launch surface examples are typical users of this carve-out.

**Scope at MVP 0.1.** Class A is left to the skill (interactive) — not yet wired into CI — because runnable example execution needs sandbox setup. Class B/C/D are deterministic and CI-safe (see `scripts/audit_docs.py` follow-up under #91).

### Class B — ADR status freshness

For every `docs/contributors/adr/*.md`:

1. Parse frontmatter `**Status:**` field. Allowed values: `Proposed`, `Accepted`, `Implementing — <details>`, `Superseded by ADR XXXX`, `Rejected`.
2. If `Status: Proposed` and the ADR body cross-references issues that are now `closed` (fetch via `gh issue view <N> --json state`), flag for status review — likely needs to flip to `Implementing` or `Accepted`.
3. If `Status: Accepted` and any **Adoption checklist** items reference issues still `open`, flag as "adoption incomplete" — note rather than block.
4. If `Status: Superseded by ADR XXXX`, verify the superseding ADR exists at `docs/contributors/adr/XXXX-*.md`.

**Worked example.** PR #92 (this skill's filing context) was an exact Class B finding: ADR 0003 said `Proposed` while slices 1–3 of #41 had merged. The check is: parse `**Status:**` line → for each `#NN` reference in the body → fetch state → if all closed and status is `Proposed`, flag.

### Class C — Section / rule cross-reference integrity

For every internal reference in markdown — `[text](path#anchor)`, `coding-rules.md §N.N`, `SKILL.md §X`, `docs/reference/...`:

1. Resolve target file exists.
2. Resolve anchor exists (markdown header → GitHub-flavored slug: lowercase, spaces→`-`, punctuation stripped).
3. Resolve rule number / section number is in the target document (grep for `### N.N` or `## §N`).
4. Flag dangling references with the file:line of the broken reference.

This class catches the most common drift after a doc renames a section or renumbers a rule.

### Class D — Cross-doc consistency for canonical contracts

The "single source of truth" docs and their derived references must stay in sync. Audit each pair:

| Source of truth | Dependent doc | What must match |
|---|---|---|
| `src/qureddy/cli.py` `EXIT_*` constants | `docs/reference/exit-codes.md` table | exit code numbers + verdict labels |
| `src/qureddy/core/models.py` Pydantic fields | `docs/reference/json-schema.md` examples | field names + types (when CBOM lands) |
| `ls .claude/skills/` directories | `CLAUDE.md` Skills table + `.claude/skills/README.md` table | every on-disk skill is listed in both indices |
| `ls docs/contributors/adr/*.md` | `CLAUDE.md` ADR list | every ADR mentioned in CLAUDE.md exists; every ADR file is mentioned |
| `find src/qureddy -name '*.py' \| wc -l` | `CLAUDE.md` "Repo state" counts | source-module count is current |
| `pytest --collect-only -q` | `CLAUDE.md` "Repo state" counts | test count is current |
| `find tests/fixtures/openssl -name '*.txt' -o -name '*.sh'` | `CLAUDE.md` fixture count | fixture counts are current |

**Worked examples.** Issue #68 (validate-fix skill missing from CLAUDE.md catalog) and issue #72 (CLAUDE.md test/source counts drifted) are both Class D findings.

The check shape: for each pair, derive the source-of-truth value mechanically (grep / wc / ls / `pytest --collect-only`), grep the dependent doc for the documented value, diff. Flag any mismatch.

## Output format

Produce this exact structure. Every finding is one row.

```markdown
## audit-docs Result

### Class A — Runnable examples
| File | Line | Command | Status | Drift |
|---|---|---|---|---|
| README.md | 42 | `qureddy scan tls www.google.com` | RAN | exit code 0, output normalized-match |
| README.md | 87 | `qureddy report` | NOT RUN | reason: skip-runnable carve-out (v1.0 surface) |

### Class B — ADR status freshness
| ADR | Status | Drift |
|---|---|---|
| 0003 | Proposed | #41 slices 1–3 closed; status should be Implementing |

### Class C — Cross-reference integrity
| Source | Reference | Target | Resolves |
|---|---|---|---|
| docs/contributors/coding-rules.md:120 | `§2.2.1` | docs/contributors/coding-rules.md | YES |
| docs/README.md:45 | `docs/old-name.md#section` | — | NO — file missing |

### Class D — Cross-doc consistency
| Source of truth | Dependent | SoT value | Doc value | Drift |
|---|---|---|---|---|
| `find src/qureddy -name '*.py' \| wc -l` | CLAUDE.md:24 | 24 | 23 | one source module added since last update |
| `ls .claude/skills/` | CLAUDE.md:55 Skills table | 7 entries | 6 entries | `validate-fix` missing |

**Summary**
- N findings (M block, P note)
- Suggested action: file issues for M; bundle P into next docs PR
- Examples that must change: <list file:line>
```

## Hard rules

- Read-only. Never edit docs or code in this skill — produce a report; the human decides.
- A row that says "no drift" is acceptable; "I didn't check" is not. If a check is skipped, say which class and why.
- For Class B (ADR status), use real `gh issue view <N> --json state` lookups — do not infer state from comments or guesses.
- For Class D, always derive the source-of-truth value mechanically. Do not eyeball a count.
- A doc that is intentionally aspirational (README's v1.0 surface) is not drift. The carve-out comment is the documented exception.

## When a finding blocks

- **Class A misses (runnable example exit code wrong)**: block the merging PR if the PR caused the drift; otherwise file an issue.
- **Class B (stale ADR status)**: never blocks — file a small docs PR.
- **Class C (broken internal link)**: block if the PR broke it; otherwise file an issue.
- **Class D (counts/catalog drift)**: never blocks alone; folded into next docs cleanup PR.

For PR-context drift, the merging PR's `audit-pr` checklist should already include "I ran audit-docs on the diff." When that box is unchecked, request a re-review.

## Companion skills

- `audit-pr` — code-side audit (size, security, scope, tests). This skill complements it.
- `run-quality-gates` — runs the actual tools (ruff/mypy/pytest/bandit). This skill audits the docs side; that one audits the code side.
- `validate-fix` — answers "did the PR resolve the issue?" — orthogonal to "does the doc still match the code?"

## Follow-up

Issue #91 tracks landing this skill. A future deterministic CI script `scripts/audit_docs.py` will mechanize Class B/C/D (Class A stays interactive). Initial CI wiring is non-blocking until the false-positive baseline tunes — same staging pattern as Semgrep in `run-quality-gates`.
