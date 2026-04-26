---
name: audit-pr
description: Audit a pull request diff against docs/CODING_RULES.md and produce the PR-template output. Use when finalizing a PR, when self-reviewing before requesting review, or when asked "is this ready to merge." This skill walks the diff, runs the Tier 1 quality gates, and produces a structured report so nothing gets skipped.
---

# Skill: audit-pr

This skill is the operational form of `docs/CODING_RULES.md` Quick Reference (Tier 1). When invoked, walk the diff line by line, then produce the structured output below.

The point of this skill is to **stop you from skimming.** A passing exit code from `pytest` is not enough. You must verify each item explicitly.

## Inputs

- The diff being audited (working tree changes, staged changes, or a PR branch)
- Optional: a target ref (compare against `main` if unspecified)

## Audit procedure

Run these in order. Do not skip steps. Capture each tool's exit code and short output.

### Step 1: Run the Tier 1 quality gates

```
ruff check .
ruff format --check .
mypy src/qureddy --strict
pytest --cov=qureddy --cov-fail-under=80
bandit -r src/qureddy
```

If any command cannot run because the project setup is incomplete (`qureddy` package not installable, no source files yet), name the missing piece. Do not skip the audit.

### Step 2: Walk the diff against CODING_RULES.md

For each Python file changed in the diff:

- **Section 2 (size):** count function lines (def to last body line, excluding blanks/docstrings); count file lines; count class lines. Flag any function over 30 (warn) or 50 (block); any file over 300 (warn) or 400 (block); any class over 200 (block).
- **Section 3 (naming):** flag any `utils.py`/`helpers.py`/`common.py` files; flag any function/class/module name that violates the conventions.
- **Section 4 (types):** confirm `from __future__ import annotations` at top; flag any public function missing type hints; flag any `# type: ignore` without a code AND comment; flag any Pydantic model without `model_config = ConfigDict(frozen=True, extra="forbid")` (or explicit justification).
- **Section 6 (errors):** flag any `except:` (bare); flag any `except Exception:` without re-raise; flag any logged-and-continued exception.
- **Section 7 (subprocess):** flag any `subprocess.run` outside `src/qureddy/scanners/tls/openssl_probe.py`; flag any string-form args (not list); flag any missing `timeout=`; flag any `shell=True`.
- **Section 8 (logging):** flag any `print()` in `src/qureddy/scanners/` or `src/qureddy/core/`; flag any f-string log message instead of k/v pairs.
- **Section 10 (comments):** flag commented-out code; flag floating TODOs without owner/issue.
- **Section 12 (security):** flag `verify=False`, `ssl.CERT_NONE`, `eval`/`exec`, `pickle.loads`; flag user-supplied paths without `.resolve()` and validation; flag `random` for security purposes (should be `secrets`).
- **Section 26 (security bar):** independent re-check of the 15 hard merge blockers.

### Step 3: Verify use case coverage (MVP 0.1 only)

If the diff touches scanner code or tests, confirm each use case in `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md` §0B has at least one corresponding test:

- UC1 (Hybrid PQ negotiation) → `tests/live/test_live_targets.py::test_pq_cloudflareresearch_hybrid` AND `tests/test_tls_parse.py`
- UC2 (Classical fallback) → `tests/live/test_live_targets.py::test_example_com_classical` AND `tests/test_policy.py`
- UC3 (SNI on IP) → `tests/live/test_live_targets.py::test_one_one_one_one_with_sni` AND `tests/test_targets.py`
- UC4 (Unsupported local OpenSSL) → `tests/test_openssl_probe.py`
- UC5 (TLS 1.3 probe failure) → `tests/live/test_live_targets.py::test_tls12_only_handshake_failure`
- UC6 (Retry transient failure) → `tests/test_retry.py`

A use case with no test fails the audit.

### Step 4: Verify changelog

If the diff changes user-visible behavior (new command, new flag, new exit code, new output field), `CHANGELOG.md` must have an entry under `[Unreleased]`. Flag if missing.

### Step 5: Verify ANTIPATTERN ACCEPTED markers

For every rule the diff intentionally violates, the PR description must contain:

```
ANTIPATTERN ACCEPTED: <rule name>, because <reason>
```

The known accepted antipattern for MVP 0.1 is the CycloneDX-flavored fields on Asset/Finding (speculative generality, accepted because schema stability matters before CBOM emission lands). Anything else needs explicit justification.

## Output format

Produce this exact structure. Do not freeform it.

```
## Audit Result

**Tier 1 quality gates:**
- ruff check: PASS / FAIL (output)
- ruff format --check: PASS / FAIL (output)
- mypy --strict: PASS / FAIL (output)
- pytest (with coverage): PASS / FAIL (X tests, Y% coverage)
- bandit: PASS / FAIL at MEDIUM (N findings)

**Diff walk against CODING_RULES.md:**
- Files changed: [list]
- Largest function: N lines in <file>:<func>
- Largest file: N lines (<file>)
- Section 2 (size): PASS / FAIL with details
- Section 3 (naming): PASS / FAIL with details
- Section 4 (types): PASS / FAIL with details
- Section 6 (errors): PASS / FAIL with details
- Section 7 (subprocess): PASS / FAIL with details
- Section 8 (logging): PASS / FAIL with details
- Section 10 (comments): PASS / FAIL with details
- Section 12 (security hygiene): PASS / FAIL with details
- Section 26 (security bar): PASS / FAIL with details

**Use case coverage (if scanner code changed):**
- UC1: covered by [test paths] / NOT COVERED
- UC2: covered by [test paths] / NOT COVERED
- UC3: covered by [test paths] / NOT COVERED
- UC4: covered by [test paths] / NOT COVERED
- UC5: covered by [test paths] / NOT COVERED
- UC6: covered by [test paths] / NOT COVERED

**CHANGELOG.md:**
- Entry present under [Unreleased] / NOT REQUIRED (no behavior change) / MISSING

**ANTIPATTERN ACCEPTED markers in PR description:**
- [list each, or NONE]

**Overall:**
- READY TO MERGE / NOT READY (block on N findings above)

**If NOT READY, blocking findings:**
1. ...
2. ...
```

## Hard rules

- Do not say "PASS" if you did not run the check. If a tool is not installed or cannot run, say "NOT RUN" with the reason.
- Do not summarize "looks good" without walking the diff.
- Do not skip use case coverage check on scanner-touching PRs.
- Do not approve PRs with even one Section 26 (security bar) violation. Refuse the merge.

## When you find a violation

Do not fix it silently. Report it in the audit output. The PR author (the user, or you in a different role) decides whether to fix or to add an `ANTIPATTERN ACCEPTED:` marker with reasoning.

If the violation is in Section 26 (security bar), the only acceptable resolution is fix-or-refuse-merge. Security exceptions go through the `SECURITY EXCEPTION ACCEPTED:` process per CODING_RULES §26.12, not silent acceptance.
