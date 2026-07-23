# Surgical-fix workflow — one bug, one narrow, test-first patch

Use this mode for: a reported defect in existing code, a failing test/lint/type/security
check, a GitHub issue describing a concrete bug, or output/behavior that contradicts the
repo's own docs or tests. This does not define a separate coding standard — the repo's own
coding-standards doc remains authoritative. This adds the bug-fix workflow on top: prove the
root cause, fix it, add the regression test, run the right checks, and self-audit the result.

Don't use this mode for: a new feature/scanner/milestone/architecture change (use the
feature-work bootstrap sequence instead), a review of someone else's proposed fix (that's a
reviewing skill's job), or a defect that only lives in scratch/experimental/archived code (fix
it in product code, or not at all — don't "fix" throwaway prior art).

## Non-negotiables

### 1. Preserve user work

Run `git status --short --branch` first. Treat any unrelated dirty files as user work in
progress — don't revert, reformat, or overwrite them.

### 2. Prove the root cause

Don't patch from the issue title alone. Name the exact function, branch, invariant, or
boundary that's wrong, in one sentence.

Bad: "JSON output is polluted." Good: "The CLI test runner merges stderr into the captured
stdout stream by default, so a test asserting JSON-stdout purity is actually reading a
combined stream, not real process stdout."

If you can't state the root cause in one sentence, keep reading and reproducing — don't patch
yet.

**Boundary/seam check.** If the bug sits at a seam between two systems — subprocess output and
its parser, a library default versus a framework override, a frozen model and its serializer,
two streams being merged, "captured at config time" versus "used at call time" — name both
contracts explicitly:

- *Whose contract is canonical?* (e.g., a structured logger's documented behavior is
  canonical; a test harness silently rebinding a stream is the side that isn't honoring it.)
- *Which side should the fix go on?* Default: fix the canonical side; adapt the other side to
  it. Don't just patch the friction point at the seam if the friction itself is the bug (e.g.
  adding a separator between two streams patches the friction; not merging them in the first
  place is the canonical fix).
- *Could the same bug class recur elsewhere?* A "captured at config time, used at call time"
  bug isn't unique to one module — anything with the same shape has the same latent bug. The
  fix should generalize to the class where it's cheap to do so.

When the seam genuinely can't be removed (cost too high, blast radius too wide), patching the
friction is acceptable — but say so explicitly in the final report under a "deferred
architectural debt" note, so the next reader knows the canonical fix was deferred on purpose,
not missed.

### 3. Test first

Add or tighten a deterministic regression test before changing production code.

- Put it in the existing test file that covers the affected module.
- Use a specific-exception assertion for error cases, not a bare exception check.
- Test observable behavior, not private implementation details, unless the private function
  is already directly tested elsewhere.
- Use a captured real fixture for parser/protocol behavior when the repo has a fixture
  convention (see `test-fixture-capture.md`) — don't invent synthetic input for something a
  real fixture could capture.
- Run the new test before the fix and confirm it fails for the intended reason — not because
  of a fixture-setup mistake or a typo in the test itself.

If no deterministic regression test is possible, stop and explain why rather than shipping an
untested fix.

### 4. Keep the patch surgical

Default patch budget:

- One production file.
- One test file.
- Optional fixture file.
- Optional one-line doc change, only if public behavior or a documented contract changed.

If the correct fix needs two or more production files, stop and report it as not surgical:
name the files the root cause actually spans, and either ask for authorization to widen scope
or recommend the feature-work bootstrap sequence instead. Don't sneak in adjacent fixes,
broad reformatting, renames, helper extraction, dependency changes, or schema cleanup under
cover of the bug fix.

### 5. Follow the repo's coding standards

Apply the target repo's own coding-standards doc to the touched code. Recurring surgical-fix
traps across this codebase family: public functions keep full type hints/docstrings; new
files carry whatever header convention the repo uses (license header, module docstring);
locked models stay locked (see `python-conventions.md`); fixed vocabularies stay enums;
exceptions are specific, not broad `except Exception`; no log-and-raise unless the log adds
context the caller can't reconstruct; no new module-level mutable state; no new
`utils.py`/`helpers.py`/vague-rename for a one-bug patch; no commented-out code or unexplained
`TODO`/`noqa`/`fmt: off`.

### 6. Respect public contracts

Bug fixes must not silently change public behavior. Treat these as contracts unless the fix
*is* an explicit, discussed contract change: CLI exit codes, stdout/stderr separation for
machine-readable output, a versioned output schema, locked model fields, distinct
failure/error categories (don't collapse two categories into one to make a bug "go away"),
and any field that's product behavior other code or other repos depend on (finding IDs,
severities, evidence structure, wire-format byte layouts, and similar).

### 7. Refuse security shortcuts

Stop instead of shipping any fix that requires: disabled TLS/certificate verification,
`shell=True` with externally-influenced input, a removed subprocess/network timeout, secret
logging, `eval`/`exec`/`pickle.loads` on untrusted input, a swallowed security-relevant error,
or a changed finding/severity/evidence value without a focused test covering the change. If
asked for one of these, say which rule blocks it and propose the secure alternative.

### 8. Bug-fix coding heuristics

Prefer the boring patch that makes the failing behavior correct: touch the causal branch, not
the surrounding architecture; prefer an explicit conditional over a new abstraction unless a
second real call site already exists; preserve existing names/boundaries unless the boundary
itself is the bug; tighten validation at the trust boundary rather than compensating
downstream; flag adjacent cleanup as a follow-up instead of folding it into the patch.

### 9. Self-audit before final response

If the repo has an anti-pattern/self-audit checklist doc, audit the diff against it before
responding. State either: `Audited against <doc>, no violations` or
`ANTIPATTERN ACCEPTED: <name>, because <reason>`. Hard failures to watch for regardless of
whether the repo has a formal checklist: hallucinated codebase knowledge, big-bang edits,
ignoring failing checks, silent behavior changes, fake certainty, speculative generality,
dependency grabs, broad exception handling, logging instead of raising, assertion-free or
implementation-detail-only tests, security shortcuts, public-contract drift without tests,
and quality theater (skipped tests, lowered thresholds, retry-count increases used to hide a
deterministic failure).

## Procedure

1. **Preflight** — `git status --short --branch`; read the issue/test/docs needed; note dirty
   files you won't touch.
2. **Reproduce** — run the smallest command that demonstrates the failure. For CLI output
   bugs, use a mode that keeps stdout and stderr genuinely separate.
3. **Diagnose** — read the code path until the root cause is concrete; note file and function;
   check whether it's product behavior, test-harness behavior, a docs mismatch, or a
   duplicate of an existing issue.
4. **Write the regression test** — add it, run it, confirm it fails for the intended reason.
5. **Patch the root cause** — smallest causal surface, existing local style, standards
   checklist applied while editing.
6. **Verify narrowly** — run the new/changed test, then the nearest affected test file(s).
7. **Verify broadly if any production code changed** — run the repo's Tier-1 local gates (see
   `python-conventions.md` / `rust-conventions.md`). If a gate is unavailable or already red
   for unrelated reasons, report that plainly — don't claim green.
8. **Self-review the diff** — confirm the patch stayed inside the stated boundary and didn't
   silently change a public contract.
9. **Final audit and report.**

## Stop conditions

Stop and ask, or escalate to the feature-work mode, when: the root cause isn't understood; a
deterministic regression test can't be written; the correct fix exceeds the surgical patch
budget; a coding-rule conflict needs a documented exception; a public-contract change is
required to make the fix correct; a security-bar rule would be violated; existing dirty
user changes block a safe patch; or required credentials/network/external state can't be
obtained.

## Final response format

```markdown
## Surgical Fix Report

**Root cause:** <one sentence with file/function/invariant>

**Changed:**
- `<path>` — <what changed>
- `<path>` — <regression test added or tightened>

**Verification:**
- `<command>` — PASS/FAIL/NOT RUN, <short evidence>

**Audit:**
- Audited against <repo's anti-pattern doc, if one exists>, no violations
- Coding standards checked against <repo's coding-standards doc>, no exceptions

**Scope:**
- Production files changed: <count>
- Test files changed: <count>
- Fixtures changed: <count>

**Follow-up:** <none, or a concrete out-of-scope issue>
```

If stopped:

```markdown
## Surgical Fix Stopped

**Reason:** <specific stop condition>
**Evidence:** <what was read/run>
**Recommendation:** <next action>
```

Never say "fixed" unless the regression test and the relevant verification actually passed.
