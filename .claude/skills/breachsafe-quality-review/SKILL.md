---
name: breachsafe-quality-review
description: General software-engineering quality review for the BreachSAFE Quantum Platform — fast local build/test/lint checks, PR diff audits against house coding rules, issue-resolution verification (does the fix actually resolve the bug, not just "tests pass"), documentation-drift sweeps, and a pre-commit anti-pattern self-check. Read-only/audit-only by default; never files issues, comments on PRs, changes labels, or pushes/merges without explicit user authorization.
---

# breachsafe-quality-review

**Applies to:** all BreachSAFE Quantum Platform (BQP) components — QuCrypt, QuCert,
QuCustody, QuReddy, Qurum — for general software-engineering quality and process review.

This is the general-purpose reviewer skill for the platform: is the code well-structured,
does it follow house style, do tests exist and pass, does a PR actually resolve the issue
it claims to, is documentation in sync with the code, are there language-idiom mistakes
that have nothing to do with cryptography being correct. It consolidates what used to be
eight separate, partially-overlapping skills spread across three repos.

## Stay in its lane

This skill does **not** cover:

- **Crypto-correctness, FIPS/RFC violations, memory-safety/timing-safety, dependency
  soundness for security purposes** → `breachsafe-security-audit`.
- **RFC/NIST citation accuracy, standards-clause conformance, known-answer-test
  execution** → `breachsafe-conformance`.
- **Supply-chain tooling (`cargo audit`/`cargo deny`/`cargo vet`), OSS release readiness
  (OpenSSF, crates.io/PyPI publish)** → `breachsafe-release`.
- **Writing/implementing the fix or feature itself** → `breachsafe-implement`.
- **Cross-repo sequencing, roadmap, ADR-vs-phase-gate sanity** → `breachsafe-pqc-pm`.

If a finding turns out to belong to one of those, say so and hand it off rather than
absorbing it here. A useful rule of thumb for the crypto boundary specifically: "would
fixing this differently change whether the cryptography is correct, or does it only
affect whether the code is well-behaved software?" The former belongs to
`breachsafe-security-audit`; the latter is this skill's job.

## Stop and read this first: authorization gate

Modes 2–4 below (PR diff audit, issue-resolution verification, doc-drift audit) are
**read-only / audit-only by default.** This skill may freely read anything — diffs, git
history, issue/PR trackers, files — but must **never**, on its own initiative:

- file or comment on an issue or PR,
- change a label,
- push, open a PR, merge, or take any other write action against a remote/shared repo
  state,
- edit code or docs it is auditing.

It may **draft** a comment, verdict, or label recommendation and present it for review.
It only posts/pushes/merges after the user gives explicit, in-conversation authorization
for that specific action. "Just post it" as part of a larger request counts as
authorization for that one action — but still show what will be posted first, and don't
chain it into further unauthorized actions.

**Mode 5 (pre-commit self-check) is the one exception**, and only partially: when
checking your own uncommitted, local work before a commit, fixing what you find is
expected and normal — see Mode 5 below for why that posture differs from auditing
someone else's code. Even there, this skill never pushes or opens a PR without
authorization; "fix your own working tree" stops at the boundary of the local checkout.

## The five modes

This skill is multi-purpose because the source material it was built from wasn't one
job — it was several related but distinct ones. Pick the mode that matches what's being
asked; don't run all five reflexively.

### Mode 1 — Fast local check

**When:** before opening a PR, or to confirm a change actually builds and the existing
suite passes, before doing anything else.

Build, run the full test suite, and lint. Language-appropriate — the exact commands
differ enough between Rust and Python that they live in separate reference files:

- Rust (QuCrypt, QuCert, QuCustody): `references/rust-quality-gates.md`
- Python (QuReddy, Qurum): `references/python-quality-gates.md`

This mode confirms the code is green. It does not confirm the code is *good* — that's
Mode 2 — or that a claimed fix actually *works* — that's Mode 3.

### Mode 2 — PR diff audit

**When:** finalizing a PR, self-reviewing before requesting review, or answering "is
this ready to merge."

Walk the diff against the target repo's own house coding-rules document, category by
category (size, naming, types/schema stability, error handling, subprocess discipline,
logging discipline, comments/dead code, general security hygiene), and produce a
structured pass/fail report. Full checklist: `references/pr-audit-checklist.md`.

Read-only by default per the authorization gate above — report findings, don't fix them,
unless explicitly authorized to do otherwise for this run.

### Mode 3 — Issue-resolution verification

**When:** a PR or patch claims to close/fix/resolve a specific tracked issue and you
need a verdict on whether it actually does, beyond "CI is green."

The guiding principle for this mode, borrowed verbatim from the sharpest framing found in
the source material: **"tests pass" and "the issue is resolved" are different
questions.** Green gates are necessary but not sufficient — a fix can have every gate
green and still miss the root cause, miss the regression test the issue called for, or
resolve something adjacent to (not the same as) what was actually reported.

This mode answers two questions in order — are the gates green (delegates to Mode 1),
and is the issue actually resolved (reproduce the bug pre-patch, confirm it's gone
post-patch, confirm the required regression test exists, confirm nothing else regressed).
Full procedure and verdict taxonomy: `references/issue-resolution-verification.md`.

Read-only. Never modifies code. If the fix is incomplete, this mode reports that — it
does not attempt to complete the fix.

### Mode 4 — Documentation-drift audit

**When:** a PR touches a public CLI surface, an output/exit-code contract, a JSON/wire
schema, or anything a doc describes; a new ADR/milestone lands; or as a periodic sweep.

Read-only sweep for documentation that was correct when written and is stale now: stale
design-record statuses, dangling cross-references, drifted counts, examples that no
longer run. This class of bug is genuinely easy to miss in normal review — nothing looks
wrong in isolation, the doc just no longer matches the code. It's also recurred
repeatedly across this platform's history: READMEs and reference docs describing APIs
that had since changed, or citing module/test/line counts that had drifted, have gone
unnoticed for extended periods more than once. That history is why this mode should run
as a recurring practice, not a one-time cleanup — drift reintroduces itself continuously
as code changes. Full procedure: `references/doc-drift-checklist.md`.

### Mode 5 — Generic anti-pattern self-check

**When:** on your own changes, before every commit.

A pre-commit checklist run against your own uncommitted, local diff. This is the mode
that fixes instead of only reporting — see the authorization-gate section above for why
that posture is different from the other four modes. Covers the generic, non-crypto
patterns: panics/unrecoverable aborts in production paths, subprocess calls outside a
repo's designated shim, stray logging in code meant to be silent, orphan source files,
unchecked narrowing casts, reimplementing logic a dependency already provides safely, and
test regressions relative to a baseline captured before the change started. Full
checklist: `references/anti-pattern-self-check.md`.

Crypto-primitive-specific anti-patterns (unsafe FFI boundaries, nonce reuse, KDF label
correctness, hedged-signature assumptions, secret-material zeroization, timing side
channels) are out of scope here — that's `breachsafe-security-audit`'s checklist. Run
both if your change touches cryptographic code.

Four of this mode's checks (panics, subprocess discipline, logging discipline, dead
code/TODOs) are shared verbatim with Mode 2's diff audit — both point at
`references/generic-code-hygiene.md` rather than each restating the checklist.

## Ground rules across all five modes

- **Verify, don't trust old text.** Never carry forward a specific pass/fail count, issue
  number, or file:line reference from a previous run or from memory into a new report.
  Numbers drift; derive them fresh every time (grep, `wc -l`, an actual test run, an
  actual tracker query).
- **No hardcoded absolute paths.** Every command and file reference in this skill and its
  references is relative to the repo being worked in. If a repo needs a specific
  environment variable to build (see `references/rust-quality-gates.md`), find its
  current value in that repo's own docs rather than assuming a path from a different
  machine or a different point in time.
- **A file this skill mentions may have moved.** If a checklist item names a module by
  role ("the module that owns subprocess calls," "the AEAD encrypt/decrypt path"), find
  the current file that plays that role rather than assuming an old filename still
  exists.
- **Don't claim you ran a check you didn't run.** Every PASS/FAIL in every report format
  in this skill's references must be backed by an actual command and its actual output.
  "NOT RUN" with a reason is always the honest fallback over a guessed PASS.
- **Structured output over prose.** Each mode has an explicit report format in its
  reference file. Use it — it's what makes the output diffable and auditable across runs.
