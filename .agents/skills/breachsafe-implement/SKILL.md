---
name: breachsafe-implement
description: Write or extend code in a BreachSAFE Quantum Platform (BQP) repo — Rust crypto crates (thin-OpenSSL-wrapper discipline) or Python scanner/tooling (locked-model, quality-gated CLI discipline) — under narrow, test-first, issue-referenced scope. Covers both new feature/extension work and single-bug surgical fixes. Does not audit, review, or decide what to prioritize.
---

# breachsafe-implement

**Applies to:** QuCrypt (`breachsafe-crypto-rs`), QuCert (`breachsafe-pki-rs`), QuCustody
(`breachsafe-custody`), QuReddy (`qureddy`), Qurum — any BQP repo where the task is writing
or extending code. Not "platform-wide" in the ADR-004 SaaS-control-plane sense; this is a
per-repo implementation skill, applied repo by repo.

## Stop and read this first: authorization gate

This skill writes code and may run local commands freely — build, test, lint, type-check,
format-check, run the app/CLI, capture fixtures. It may also do local, non-destructive git
inspection and staging: `git status`, `git diff`, `git log`, `git add`.

It must **never**, on its own initiative:

- commit, push, create or switch branches, open a PR, merge, tag, or run any other git
  operation that changes repo history or remote state,
- close or comment on a GitHub issue,
- run destructive git commands.

If the repo's own workflow docs describe committing on a feature branch and opening a PR as
part of "the fix workflow," treat that language as describing the *end state* the human
wants, not standing authorization to execute it. Stage the change, show the diff, and ask —
or wait for explicit in-conversation authorization — before any git write.

## Stay in its lane

This skill implements. It does not decide what to build, and it does not grade its own work.
If the actual ask is one of these, say so and point at the right skill instead of doing it
here:

- Deciding what to build / sequencing / roadmap → `breachsafe-pqc-pm`
- Correctness/quality review of a diff → `breachsafe-quality-review`
- Security-focused audit → `breachsafe-security-audit`
- Standards/spec conformance (RFC/FIPS/NIST) → `breachsafe-conformance`
- Release mechanics (versioning, changelog, publish) → `breachsafe-release`

This skill's job starts once "what to build" is already decided (an issue, a spec, a bug
report) and ends once code and its tests are written and passing locally. Running the local
test/lint loop while implementing is normal and expected; a formal Tier-1 gate sign-off or PR
audit is the reviewing skill's job, not this one's.

## Two modes of work

**New feature / extension** — building something that doesn't exist yet, or extending an
existing module within a defined scope (a milestone spec, a locked schema, an open issue).
Follow the bootstrap-reading sequence below, then build in the order the spec/milestone doc
lays out. Full detail: `references/bootstrap-reading.md`.

**Narrow bug fix** — one reported defect, one root cause, one small patch. This has its own
tighter discipline: prove the root cause in one sentence, write the regression test before
the patch, keep the patch surgical, stop and escalate if it stops being narrow. Full
protocol: `references/surgical-fix-workflow.md`.

If you're not sure which mode you're in: if the change needs more than roughly one production
file plus one test file (plus maybe a fixture), it's feature work, not a surgical fix — use
the feature-work bootstrap sequence instead of trying to force it through the narrow-fix
budget.

## Before you write any code

Every BQP repo has its own orientation doc, coding-standards doc, architecture doc, and
sometimes a locked-scope/locked-schema doc for the feature in flight. Read them in that
order, every time, before touching code — a stale mental model from a previous session is
the single most common source of wrong-shaped patches in this codebase family.

The generalized sequence and the current known doc locations per repo are in
`references/bootstrap-reading.md`. One thing worth stating up front because it bit this
skill's own authoring session: **when a repo's `CLAUDE.md`/`AGENTS.md` prose and its
architecture doc (or the actual file tree) disagree about file layout, the architecture doc
and the actual tree win.** Onboarding docs go stale about file paths faster than architecture
docs do. Verify structural claims (module layout, file names) against the real tree with
`ls`/`find` before trusting either doc, and flag the drift if you find it.

## Language-specific discipline

- **Rust (QuCrypt/QuCert/QuCustody style)** — thin-wrapper-over-a-library discipline, unsafe
  scoping, secret-zeroization discipline, fail-closed error handling, fixed-size wire-format
  invariants. `references/rust-conventions.md`.
- **Python (QuReddy/Qurum style)** — locked Pydantic model discipline, subprocess-boundary
  discipline, structured logging, the project's quality-gate command set.
  `references/python-conventions.md`.

## The cross-cutting principle: don't reimplement the library

Across both languages, the architectural discipline is the same shape: **this codebase family
wraps a well-vetted external implementation; it does not reimplement what that implementation
already provides.** In the Rust crypto crates, that means every byte of cryptographic
transformation goes through an OpenSSL EVP call — no hand-rolled AES/SHA/HMAC/KDF math, no
custom signature encoding, no second crypto backend. In the Python scanner tools, the
equivalent is: the actual TLS/crypto behavior under test comes from a real OpenSSL subprocess,
not a reimplementation or a mocked simulation of what OpenSSL would do — and there is
exactly one module boundary where that subprocess gets invoked, not several.

If you find yourself writing logic that reproduces what the underlying library/protocol
implementation already does correctly, stop and find the call that does it instead. If no
safe wrapper exists for a needed operation, isolate the unsafe/raw call behind the smallest
possible boundary (a single named FFI shim file in Rust; a single named subprocess-boundary
module in Python) rather than letting it spread.

## Test-first, always

Write the test — a regression test for a bug, a fixture-driven test for a new parser case, a
unit test for new logic — before or alongside the code, and confirm it fails for the expected
reason before you make it pass. When the test needs real output from an external tool
(OpenSSL, or any other subprocess-driven dependency), capture a real fixture rather than
inventing one. Full capture protocol: `references/test-fixture-capture.md`.

## Scope discipline

- Build only what was asked. Note out-of-scope opportunistic fixes as a comment or a
  follow-up, don't fold them into this change.
- No placeholder scaffolding: every file you create must be exercised by the command path,
  by a test, or by tooling those require. If a file can't participate in the working path or
  tests, don't create it — say why in your response instead.
- If a locked schema, locked model, or locked CLI contract exists for the area you're
  touching, treat it as locked: don't add fields, rename, retype, or drop them without the
  scope explicitly authorizing it. If you must deviate, say so explicitly rather than doing
  it silently — see the `ANTIPATTERN ACCEPTED:` / `ASSUMPTION:` escape hatches in
  `references/python-conventions.md` and `references/surgical-fix-workflow.md`.
- Don't add dependencies casually. Every non-trivial addition should be traceable to a real
  requirement in the spec/issue, not convenience.

## When you finish

Report plainly, anchored to commands actually run (don't claim a check passed without running
it):

1. What you implemented or fixed, and where (file paths).
2. The regression/coverage test(s) added, and their result.
3. Commands run locally (build/lint/type-check/test) and their outcomes — PASS/FAIL/NOT RUN,
   never "looks fine."
4. What you intentionally left out of scope, and why.
5. Any `ASSUMPTION:` or `ANTIPATTERN ACCEPTED:` markers, stated explicitly rather than buried.
6. That no git write operations were performed unless the user explicitly authorized them,
   and if any local staging (`git add`) happened, say so.

## References

- `references/bootstrap-reading.md` — the generalized "read these before writing code"
  sequence, and current known doc locations per repo.
- `references/rust-conventions.md` — thin-wrapper discipline, unsafe scoping, secret
  handling, and the current real module layout for the Rust crypto crates.
- `references/python-conventions.md` — locked-model discipline, subprocess-boundary
  discipline, structured logging, and the quality-gate command set.
- `references/surgical-fix-workflow.md` — the narrow-scope bug-fix protocol: root-cause
  proof, patch budget, stop conditions, final report format.
- `references/test-fixture-capture.md` — capturing real subprocess-output fixtures for
  parser tests, with redaction rules and naming conventions.
