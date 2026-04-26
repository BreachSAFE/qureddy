---
name: run-quality-gates
description: Run the QuReddy Tier 1 per-PR quality gates and report results structurally. Use as a pre-final-response check on any code-touching task. The skill enforces "do not claim a check passed without running it" by structuring the output around what was actually executed.
---

# Skill: run-quality-gates

Operational form of CODING_RULES §22 Tier 1 gates. Run before final response on any code-touching task.

The point of this skill: stop you from saying "tests pass" without running them. Every claim in the output below is anchored to a real command and its real exit code.

## When you invoke this skill

- Before producing a final response on a task that touched any file under `src/qureddy/` or `tests/`
- When the user asks "are we ready" or "can this merge"
- When opening a PR

If you didn't touch any code, you don't need this skill. Skip to the response.

## Procedure

Run these commands in order. Capture each command's exit code and short output (truncate to ~5 lines per command).

### 1. Lint

```
ruff check .
```

Pass criterion: exit code 0.

### 2. Format check (verify-only, never rewrites)

```
ruff format --check .
```

Pass criterion: exit code 0. **Do not run `ruff format .` (without `--check`)** unless the user explicitly asked for a formatting-only task. Per CODING_RULES §1.5, mechanical formatting is a separate commit.

### 3. Type check

```
mypy src/qureddy --strict
```

Pass criterion: exit code 0. No implicit Any. No untyped functions.

### 4. Static security

```
bandit -r src/qureddy
```

Pass criterion: 0 findings at MEDIUM or higher. LOW findings are reported but do not block.

### 5. Dependency vulnerability scan

```
pip-audit
```

Pass criterion: 0 HIGH or CRITICAL CVEs. MEDIUM and below reported but do not block. Failures here often reflect upstream CVE disclosures, not your code — investigate, do not lower the threshold.

### 6. Dependency hygiene

```
deptry .
```

Pass criterion: exit code 0. Catches dependencies declared in `pyproject.toml` but unused, and imports without a corresponding declared dependency.

### 7. License header compliance

```
reuse lint
```

Pass criterion: exit code 0. Every source file has an SPDX header (`# SPDX-License-Identifier: Apache-2.0`).

### 8. Semgrep (report-only at MVP 0.1)

```
semgrep scan --config auto .
```

Findings are reported but **do not block** MVP 0.1. Semgrep promotes to blocking once false-positive baseline is tuned (later milestone). Do not silence Semgrep findings in code without an explicit `# nosemgrep:<rule-id>  # <reason>` comment.

### 9. Secret scan on diff

If `gitleaks` is installed:

```
gitleaks detect --no-git --source .
```

If `trufflehog` instead:

```
trufflehog filesystem --no-update .
```

Pass criterion: 0 verified secrets. Unverified detections are reported but do not block.

### 10. Tests with coverage

```
pytest --cov=qureddy --cov-fail-under=80
```

Pass criterion: exit code 0. All tests run. Coverage >= 80%.

`pytest-rerunfailures` provides 3 retries with 1s delay automatically (configured in `pyproject.toml`). Live network tests in `tests/live/` run as part of the default suite — there is no `-m` marker to add.

If the test runs ended with `Rerun:` markers, that means a transient failure was absorbed. Note this in the output but do not flag as a failure.

### 11. Audit script (when it exists)

```
python scripts/audit_phase.py
```

Pass criterion: exit code 0. Verifies that the prior phases produced expected artifacts and counts.

If `scripts/audit_phase.py` does not yet exist (pre-MVP-0.1-implementation state), skip with note `audit_phase.py not yet present — skipping`.

## Output format

Produce this exact structure. **Every row must reflect what actually happened.** "PASS" without running the check is forbidden.

```
## Quality Gates Result

| Gate | Command | Status | Notes |
|---|---|---|---|
| Lint | `ruff check .` | PASS / FAIL / NOT RUN | |
| Format check | `ruff format --check .` | PASS / FAIL / NOT RUN | |
| Type check | `mypy src/qureddy --strict` | PASS / FAIL / NOT RUN | |
| Static security | `bandit -r src/qureddy` | PASS / FAIL / NOT RUN | MEDIUM threshold |
| Dep CVEs | `pip-audit` | PASS / FAIL / NOT RUN | HIGH/CRITICAL block |
| Dep hygiene | `deptry .` | PASS / FAIL / NOT RUN | unused / missing imports |
| License headers | `reuse lint` | PASS / FAIL / NOT RUN | SPDX on every source file |
| Semgrep (report-only) | `semgrep scan --config auto .` | PASS / FAIL / NOT RUN | findings reported, do not block at MVP 0.1 |
| Secret scan | `gitleaks detect ...` (or `trufflehog filesystem ...`) | PASS / FAIL / NOT RUN | which tool used |
| Tests + coverage | `pytest --cov=qureddy --cov-fail-under=80` | PASS / FAIL / NOT RUN | N tests, X% coverage |
| Audit script | `python scripts/audit_phase.py` | PASS / FAIL / NOT RUN / NOT YET PRESENT | |

**Summary:**
- All blocking gates: PASS / N gates failed / N gates NOT RUN
- Semgrep findings (report-only): N (does not block)
- Ready for merge: YES / NO (block on N failed) / NO (block on N not-run gates)

**If any gate FAILED, the failure output (truncated to relevant lines):**
```
[paste]
```

**If any gate was NOT RUN, the reason per gate:**
- Lint: tool not installed / command syntax error / etc.
```

## Hard rules

- Do not write "PASS" if you didn't run the command. Use "NOT RUN" with a reason.
- Do not paraphrase tool output. Use the actual exit code and a verbatim short excerpt.
- Do not skip gates because "they're probably fine." If the project is too pre-MVP for a gate to apply, report NOT RUN with reason.
- Do not run `ruff format .` to "fix" formatting failures. That violates §1.5. Surface the failure.
- Do not raise the `pytest-rerunfailures` retry count to mask a flaky test you wrote. Per CODING_RULES Rule 9.5.

## When a gate fails

The gate failure is surfaced. Resolution is the PR author's call:

1. Fix the underlying issue, re-run gates, repeat until green
2. If the gate is wrong (rare), open a CODING_RULES discussion per §20
3. If the failure is a known infra issue (network blip, runner flake), note it and re-run; do not raise retry counts

For Tier 1 security gate failures (bandit MEDIUM+, secret scan, security bar), the only acceptable resolution is fix-then-re-run. The merge does not happen with security gates red.
