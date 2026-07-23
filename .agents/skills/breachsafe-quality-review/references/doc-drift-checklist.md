# Documentation-drift audit (Mode 4)

Read-only sweep for documentation that was accurate when written and is stale now. This
class of bug is easy for human review to miss, because nothing about it looks wrong in
isolation — the doc reads fine, it just no longer matches the code. Across this
platform's history, exactly this class of bug — READMEs and reference docs describing
APIs that had since changed, or citing module/test/line counts that had drifted out of
date — has shown up repeatedly and gone unnoticed for a long time before being caught.
That's the reason this mode exists as a recurring practice rather than a one-time
cleanup: doc drift reintroduces itself continuously as code changes, so the sweep needs
to run periodically, not just once.

This mode never edits docs or code. It produces a report; a human (or an explicitly
authorized follow-up action) decides what to fix.

## When to run this

- A PR touches a public CLI surface, an output/exit-code contract, a JSON/wire schema, or
  anything a doc describes.
- A new design-decision record (ADR) or milestone is added, or a milestone closes.
- Periodic sweep — this is the mode that most benefits from being run on a schedule
  rather than only reactively.
- Someone asks "are the docs still in sync with the code?"

If a diff is a pure internal refactor with no doc-relevant surface change, this mode can
be skipped for that diff.

## Four classes of check

Run each class in order. Cite file path + line for every finding — never paraphrase
"some docs look stale."

### Class A — Runnable example execution

For every fenced code block in READMEs, tutorials, how-tos, and reference docs that's
tagged as a shell/console example:

1. Extract the command.
2. If it's safe and self-contained to actually run (no destructive side effects, no
   requirement for credentials this session doesn't have), run it and capture exit code
   + output.
3. Compare against any documented expected output nearby, normalizing volatile values
   (timestamps, durations, version strings) before comparing.
4. Flag mismatches: wrong exit code, missing subcommand/flag, output diverges past
   normalization tolerance.

A code block explicitly marked as intentionally aspirational or not-yet-implemented
(check for a skip/carve-out marker convention in the repo) is not drift — the marker is
the documented exception. Don't flag it, but do confirm the marker itself still applies
(e.g. the feature it's waiting on hasn't actually shipped since the marker was added).

### Class B — Design-record / status freshness

For every architecture/design decision record (ADR) or similarly status-tagged document:

1. Read the status field.
2. If the status implies "not yet decided" or "not yet implemented" but the work it
   describes has since landed (check linked issues/PRs for closed/merged state via the
   repo's actual tracker — don't infer from memory or guesswork), flag the status as
   stale and needing an update.
3. If the status says "superseded by X," confirm X actually exists.

### Class C — Cross-reference integrity

For every internal doc-to-doc reference (markdown links, "see §N.N" style citations,
"see SKILL.md" pointers):

1. Confirm the target file exists.
2. Confirm the target anchor/section exists in that file.
3. Flag dangling references with the file:line of the broken reference.

This class catches the most common drift after a doc gets renamed or a section gets
renumbered elsewhere.

### Class D — Cross-doc consistency for canonical contracts

Some values have exactly one source of truth and one or more docs that restate it (a
count of modules, a count of tests, a catalog of skills, a list of exit codes). For each
such pair in the target repo:

1. Derive the source-of-truth value mechanically — grep, `wc -l`, `find`, `ls`, a test
   collector (`pytest --collect-only`), whatever actually counts it. Never eyeball a
   count.
2. Read the documented value.
3. Diff. Flag any mismatch.

Typical pairs worth checking in a BQP repo: on-disk skill directories vs. any catalog
table that lists them; on-disk ADR files vs. any ADR index; source module count vs. a
"repo state" summary in a CLAUDE.md-style file; collected test count vs. a documented
test count; fixture file count vs. a documented fixture count.

## Output format

```
## Doc-Drift Audit Result

### Class A — Runnable examples
| File | Line | Command | Status | Drift |
|---|---|---|---|---|

### Class B — Status freshness
| Doc | Status | Drift |
|---|---|---|

### Class C — Cross-reference integrity
| Source | Reference | Target | Resolves |
|---|---|---|---|

### Class D — Cross-doc consistency
| Source of truth | Dependent doc | SoT value | Doc value | Drift |
|---|---|---|---|---|

**Summary:** N findings (M block, P note). Suggested action.
```

## Hard rules

- Read-only. Never edit docs or code as part of this mode — report, don't fix, even
  though the fix is often trivial. The point is a deliberate human (or explicitly
  authorized) decision point, not silent correction.
- "No drift found" is an acceptable row. "I didn't check this class" is not — if a class
  is genuinely skipped for this run, say which one and why.
- For Class B, use a real state lookup against the actual issue/PR tracker — don't infer
  status from comments or assumptions.
- For Class D, always derive the source-of-truth value mechanically, never by eyeballing.
- An intentionally aspirational doc (a documented future-facing example, clearly marked
  as such) is not drift by itself — but check the marker's premise still holds.
