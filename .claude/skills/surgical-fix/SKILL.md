---
name: surgical-fix
description: Fix one QuReddy Python bug with a narrow, test-first patch. Use for reported bugs, regressions, failing tests, wrong CLI output, parser errors, subprocess failures, or security-sensitive behavior defects. Enforces root-cause proof, coding-rules compliance, anti-pattern audit, focused verification, and stop/escalate behavior when the fix is no longer surgical.
---

# Skill: surgical-fix

Operational protocol for fixing one Python bug without turning it into a refactor, feature, cleanup pass, or standards rewrite.

This skill does not define a separate coding standard. `docs/contributors/coding-rules.md` remains the authority for code. This skill adds the bug-fix workflow on top: **prove the bug, fix the root cause, add the regression test, run the right checks, and audit the result against project anti-patterns.**

## Load First

Before editing, read only the relevant parts of these files:

- `CLAUDE.md` — project orientation, current milestone, command surface, skill table
- `docs/contributors/agent-antipatterns.md` — operating discipline and final audit checklist
- `docs/contributors/coding-rules.md` — Python authoring rules, tests, output, subprocess, security bar
- `docs/contributors/examples.md` — when touching a pattern shown there: models, pytest, subprocess, logging, CLI, JSON
- `.claude/skills/run-quality-gates/SKILL.md` — before final verification on code-touching work

If the bug is tied to a GitHub issue, read the full issue body and comments before editing:

```bash
gh issue view <number> --repo breachsafe/qureddy --comments
```

## Use This Skill When

- A user reports wrong behavior in existing Python code.
- A unit, integration, live, lint, type, or security check is failing.
- A GitHub issue describes a concrete defect.
- CLI output, JSON output, logging, parser, target parsing, subprocess, retry, or error handling behaves contrary to the docs or tests.

## Do Not Use This Skill When

- The request is a new scanner, feature, milestone, or architecture change — use `mvp-implement`.
- The task is only to review another agent's proposed fix — use `python-oss-crypto-reviewer`.
- The task is only PR finalization — use `audit-pr`.
- The defect lives only in `scratch/` or archived prior-art work — do not fix it in product code.
- The root cause spans multiple product areas and requires design work — stop and escalate.

## Non-Negotiables

### 1. Preserve User Work

Run `git status --short --branch` first. Treat unrelated dirty files as user work. Do not revert, reformat, or overwrite them.

### 2. Prove the Root Cause

Do not patch from the issue title alone. Name the exact function, branch, invariant, or boundary that is wrong.

Bad: "JSON output is polluted."

Good: "`CliRunner` mixes stderr into `result.stdout` by default, so tests that assert JSON stdout purity are reading a combined stream rather than real process stdout."

If you cannot state the root cause in one sentence, keep reading and reproducing.

**Boundary / seam check.** If the bug sits at a seam between two systems — subprocess output and parser, library default and framework override, frozen model and serializer, two streams (stdout+stderr) being merged, capture-at-config-time vs use-at-call-time — name BOTH contracts explicitly:

- *Whose contract is canonical?* (e.g. structlog says "logs go to the file you give me at config time" — that's canonical; `CliRunner.mix_stderr=True` rebinding `sys.stderr` is the other side, which canonical-side does not honor.)
- *Which side should the fix go on?* Default: fix the canonical side. Adapt the other side to it. Don't just patch the friction point at the seam (e.g. adding a `\n` separator between stdout and stderr is patching the friction; the canonical fix is to not merge them at all, or to give each its own parser pass).
- *Could the same bug class recur elsewhere?* Capture-at-config-time bugs aren't unique to logging — any module that snapshots `sys.stdout`/`stderr` at import time has the same shape. The fix should generalize to the class, not just the instance.

When the seam can't be removed (cost too high, blast radius too wide), patching the friction is OK — but call it out in the Surgical Fix Report under "Architectural debt" so the next reader knows the canonical fix was deferred, not invisible.

### 3. Test First

Add or tighten a deterministic regression test before changing production code.

- Put it in the existing `tests/test_*.py` file that covers the affected module.
- Use `pytest.raises(SpecificError)` for error cases.
- Test public behavior, not private implementation details, unless the private function is already directly tested.
- Use captured fixtures for parser/protocol behavior when available.
- Run the new test before the fix and confirm it fails for the expected reason.

If no deterministic regression test is possible, stop and explain why. Do not ship an untested fix.

### 4. Keep the Patch Surgical

Default patch budget:

- One production file under `src/qureddy/`
- One test file
- Optional fixture file
- Optional docs line only if public behavior or documented contract changes

If the correct fix needs two or more production files, stop and report:

`Not surgical — root cause spans <files>. Escalate to mvp-implement or ask for approval to widen scope.`

Do not sneak in adjacent fixes, broad formatting, renames, helper extraction, dependency changes, or schema cleanup.

### 5. Follow Python Standards

Apply `docs/contributors/coding-rules.md` to the touched code. The most common surgical-fix traps:

- Public functions keep full type hints and docstrings.
- New Python files need SPDX, module docstring, and `from __future__ import annotations`.
- Pydantic models stay frozen with `extra="forbid"` unless explicitly justified.
- Fixed vocabularies use `Enum`, not raw strings.
- Collections that do not mutate should be tuples.
- Datetimes are timezone-aware UTC.
- Imports stay top-level, absolute, and grouped as stdlib, third-party, first-party.
- Environment is read at CLI boundaries, not inside business logic.
- Exceptions are specific project exceptions from `core/errors.py`; no bare `Exception` or broad catch without a process-boundary reason.
- Exception transformations preserve cause with `raise X from e`, unless the original exception is intentionally irrelevant to user output.
- No log-and-raise unless the log adds context the caller cannot add.
- No module-level mutable state. Use frozen constants, tuples, strings, ints, or Enums.
- OpenSSL subprocess calls stay in `src/qureddy/scanners/tls/openssl_probe.py`, use list args, `shell=False`, timeout, captured stdout/stderr, `check=False`, and manual return-code handling.
- Logs are structured key/value calls, not f-strings.
- Logs go to stderr; scan output goes to stdout. JSON stdout must stay parseable.
- JSON output uses `model.model_dump(mode="json")`; do not hand-build schema output.
- Findings, evidence, assets, and dependencies stay deterministically ordered.
- No `utils.py`, `helpers.py`, vague renames, or new abstractions for a one-bug patch.
- No commented-out code, unexplained `TODO`, bare `# noqa`, or `fmt: off`.

### 6. Respect Public Contracts

Bug fixes must not silently change public behavior. Treat these as contracts:

- CLI exit codes: `0` success, `2` target scan failed, `3` local dependency problem, `4` usage/configuration error.
- stdout/stderr separation: scan results only on stdout; logs, progress, and errors on stderr.
- JSON schema: current schema is `qureddy.scan.v1`; removing or renaming fields requires an explicit schema decision.
- Pydantic model fields: frozen models with `extra="forbid"` reject unknown fields. New fields need a skill/spec update, tests, and schema review.
- Failure categories: do not collapse distinct categories such as timeout, connect failure, handshake failure, or local OpenSSL capability failure.
- Finding IDs, severities, and evidence fields are product behavior and require focused tests when changed.

### 7. Refuse Security Shortcuts

Stop instead of implementing any fix that requires:

- `verify=False`, disabled TLS verification, or weakened certificate handling
- `shell=True` with user-controlled input
- removed subprocess/network timeouts
- secret logging
- `eval`, `exec`, or `pickle.loads` on untrusted input
- swallowed security-relevant errors
- changed findings, severities, or evidence without focused tests

If the user asks for one of these, say which security-bar rule blocks it and propose the secure alternative.

### 8. Use Bug-Fix Coding Heuristics

Prefer the boring patch that makes the failing behavior correct.

- Touch the causal branch, not the surrounding architecture.
- Prefer an explicit conditional over a new abstraction unless there is already a second real call site.
- Preserve existing names and module boundaries unless the bug is caused by the boundary itself.
- Tighten validation at the trust boundary instead of compensating downstream.
- Keep parser fixes fixture-driven when fixtures exist.
- Keep CLI fixes observable through exit code, stdout, stderr, and JSON shape, not private implementation details.
- Keep subprocess fixes inside the probe module and test args, timeout, return code, stdout, stderr, and exception mapping.
- Keep retry fixes explicit about which failure categories retry and which fail immediately.
- Add comments only for non-obvious protocol, security, or platform constraints.
- Flag adjacent cleanup as follow-up instead of including it in the patch.

### 9. Audit Anti-Patterns

Before final response, audit the diff against `docs/contributors/agent-antipatterns.md`.

Hard failures for this skill:

- Hallucinated codebase knowledge
- Big bang edits
- Ignoring failing checks
- Silent behavior changes
- Fake certainty in final answers
- Speculative generality
- Dependency grabs
- Broad exception handling
- Logging instead of raising
- Weak tests, assertion-free tests, or tests that only verify implementation details
- Security shortcuts
- Public contract drift without tests and documentation
- Quality theater, including skipped tests, lowered thresholds, or retry-count increases to hide deterministic failures

Final response must include either:

`Audited against docs/contributors/agent-antipatterns.md, no violations`

or:

`ANTIPATTERN ACCEPTED: <name>, because <reason>`

## Procedure

1. **Preflight.**
   Run `git status --short --branch`. Read the issue/test/docs needed for this bug. Identify dirty files you will not touch.

2. **Reproduce.**
   Run the smallest command that demonstrates the failure. Prefer one targeted pytest node. If the bug is CLI output, use a command or `CliRunner` mode that distinguishes stdout from stderr.

3. **Diagnose.**
   Read the code path until the root cause is concrete. Note file and function. Check whether this is product behavior, test harness behavior, docs mismatch, or duplicate issue.

4. **Write the regression test.**
   Add the failing test. Run it. Confirm it fails for the intended reason, not because of fixture setup or a typo.

5. **Patch the root cause.**
   Edit the smallest causal surface. Preserve existing local style. Do not create a generic helper unless a second real call site already exists. Apply the coding standards and public-contract checklist above while editing.

6. **Verify narrowly.**
   Run the new/changed test. Then run the nearest affected test file. For parser, CLI, output, subprocess, target parsing, model, or security changes, run the relevant neighboring tests too.

7. **Verify broadly when needed.**
   If any product code under `src/qureddy/` changed, use `.claude/skills/run-quality-gates/SKILL.md` or run its relevant gates. At minimum:

   ```bash
   ruff check .
   ruff format --check .
   mypy src/qureddy --strict
   pytest --cov=qureddy --cov-fail-under=80
   bandit -r src/qureddy
   ```

   If a gate is unavailable or pre-existing red, report it plainly. Do not claim green.

8. **Self-review the diff.**
   Inspect `git diff --check` and `git diff --stat`. Confirm the patch stayed inside the stated boundary, did not alter public contracts silently, and did not introduce a coding-rules exception.

9. **Final audit and report.**
   Run the anti-pattern audit and the surgical-fix coding checklist. Report exact commands and outcomes.

## Stop Conditions

Stop and ask or escalate when:

- The root cause is not understood.
- A deterministic failing test cannot be written.
- The correct fix needs more than the surgical patch budget.
- A coding-rule conflict requires a documented exception.
- A public contract change is required to make the fix correct.
- A security-bar rule would be violated.
- Existing dirty user changes block a safe patch.
- Required credentials, network access, or external service state cannot be obtained.

## Final Response Format

Use this structure:

```markdown
## Surgical Fix Report

**Root cause:** <one sentence with file/function/invariant>

**Changed:**
- `<path>` — <what changed>
- `<path>` — <regression test added or tightened>

**Verification:**
- `<command>` — PASS/FAIL/NOT RUN, <short evidence>

**Audit:**
- Audited against `docs/contributors/agent-antipatterns.md`, no violations
- Coding standards checked against `docs/contributors/coding-rules.md`, no exceptions

**Scope:**
- Production files changed: <count>
- Test files changed: <count>
- Fixtures changed: <count>

**Follow-up:** <none, or concrete out-of-scope issue>
```

If stopped:

```markdown
## Surgical Fix Stopped

**Reason:** <specific stop condition>
**Evidence:** <what was read/run>
**Recommendation:** <next action>
```

Never say "fixed" unless the regression test and relevant verification actually passed.
