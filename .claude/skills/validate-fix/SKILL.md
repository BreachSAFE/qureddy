---
name: validate-fix
description: Validate that a single PR actually resolves the GitHub issue(s) it claims to fix. Use when a fix has been proposed (PR opened/updated) and you need a verdict on whether the bug is gone, the regression test is in place, and no previously-passing test was broken. Read-only on the PR diff. Posts a structured PR comment with a machine-parseable verdict and applies a `validation:claude:<verdict>` label. Distinguishes "tests pass" from "issue resolved" — those are different questions.
---

# Skill: validate-fix

This skill is the bridge between issue intent and CI mechanics. CI says "tests pass" or "tests fail." This skill says "the bug from issue #N is reproducible before this patch and gone after." Different question, different signal.

The point of this skill: **stop a PR that claims to fix a bug from merging when the bug isn't actually fixed.** Green gates are necessary but not sufficient — a PR can have green gates and still miss the root cause, miss the required regression test, or fix something other than what the issue described.

## When you invoke this skill

- A PR has been opened or updated that references at least one issue (e.g. `Closes #17`, `Fixes #19`).
- You need to know whether the PR actually resolves the bug, beyond "tests pass."
- A reviewer (`python-oss-crypto-reviewer`) wants a second signal independent of their verdict.
- Codex (Arbiter) is about to merge and wants a final mechanical check.

## When you do NOT invoke this skill

- **No issue reference in the PR.** Refuse the run. The skill needs an issue body to validate against — no issue = no expected-behavior contract = nothing to validate. Tell the user to add `Closes #N` to the PR description.
- **PR is draft.** Drafts are works-in-progress. Wait until ready-for-review.
- **PR has merge conflicts.** Fix conflicts before validating; the diff isn't stable.
- **The fix author wants help fixing the bug.** Use `surgical-fix`. This skill is read-only.
- **Reviewing whether the fix is *correct* in approach (root cause vs symptom).** Use `python-oss-crypto-reviewer`. This skill validates mechanical resolution, not architectural correctness.

## Two questions, separated

This skill answers two questions, in order. They are NOT the same question. The verdict separates them.

### Question 1: Are the gates green?

Delegated to `run-quality-gates`. Standard Tier 1 sweep: `ruff check`, `ruff format --check`, `mypy --strict`, `pytest` (full suite, no `-k` filter, no skip markers, with coverage), `bandit`, plus the wider `just gates` set (`pip-audit`, `deptry`, `reuse`, `semgrep`, secret scan).

Pass criterion: every gate exits 0.

### Question 2: Is the issue actually resolved?

This is the value-add over `run-quality-gates`. It has four sub-checks:

1. **Pre-patch reproduction.** Check out the PR's base commit (the commit immediately before the patch). Run the issue's `### Reproduction` block. Assert it fails — i.e., the bug exists before the patch. If it doesn't fail, the bug is not present on the base, so the PR isn't fixing what it claims; mark `needs-clarification` and stop.
2. **Patched-state reproduction.** Check out the PR's HEAD. Run the issue's `### Reproduction` again. Assert it now succeeds (or the previously-failing assertion now holds).
3. **Required regression test present.** If the issue body has `### Test additions required` or `### Suggested fix` mentions specific tests, assert those tests are in the PR's diff and they pass.
4. **No regression introduced.** Compare the pre-patch test set's pass/fail outcomes against the patched state. Any test that was passing before and fails now is a regression — automatic `failed`.

## Hard rules

These are non-negotiable. If a rule blocks the validation, the skill stops and the response says so.

### 1. Read-only on code.

The skill never modifies code. Not the PR's diff, not other tests, not config. If the validator finds a problem, it reports — it does not patch.

If a fix is needed, hand off to `surgical-fix` or to the original PR author. The validator stays in its lane.

### 2. One PR per run.

Validate exactly one PR. Multi-PR validation invites scope confusion ("which PR caused the regression?"). Single PR, single verdict.

### 3. Must reference at least one issue.

Refuse the run with: `validate-fix STOPPED: PR has no issue reference. Add 'Closes #N' or 'Fixes #N' to the PR description.`

If the PR references multiple issues, validate against each separately and produce a per-issue verdict in the output.

### 4. Validate-on-merits, not architecture.

If the issue body recommends Option A and the PR takes Option B with no explanation, that is a re-review trigger for `python-oss-crypto-reviewer` — not for this skill. **The validator validates whether the chosen approach works, not whether it was the right approach.**

If the PR's approach passes all four sub-checks of Question 2, validate it. The reviewer's job is the disagreement; the validator's job is "does this work."

### 5. Pre-patch reproduction is hard-required.

If the issue's `### Reproduction` cannot be run on the base commit (missing fixtures, requires network state, requires a specific OpenSSL version not available in CI), STOP and produce verdict `needs-clarification`. Do NOT skip the pre-patch repro and validate only the patched state — without proof that the bug existed before the patch, "tests pass" is not evidence the bug is fixed.

The user (or the issue author) needs to either:
- Add a deterministic reproduction to the issue body, or
- Pin the issue as "non-reproducible-locally; trust the patched-state behavior" — which is a maintainer call, not the validator's.

### 6. Comments are append-only.

Never edit prior validation comments. Each run produces a new comment with the round number incremented. The label `validation:claude:<verdict>` may be swapped (latest verdict wins), but only after the new comment is posted with `addresses-comment-id` naming the prior validation.

### 7. Refuse to validate during the disagreement window.

If `python-oss-crypto-reviewer` has posted a `review:claude:reject` or `review:codex:reject` on this PR within the last hour, do NOT validate. The reviewer-vs-PR-author conversation must resolve first. Validating during disagreement adds noise and may green-light a fix the reviewer is asking to be reverted.

If you must validate (e.g., maintainer override), include `acknowledged-review-rejection: <comment-id>` in the validation comment header.

## Procedure

1. **Pull the PR.** `gh pr view <n> --json number,title,body,baseRefName,headRefName,headRefOid,isDraft,mergeable,labels`. Confirm: not draft, mergeable, has at least one issue reference.
2. **Extract issue references.** Parse PR body and commit messages for `Closes #N`, `Fixes #N`, `Resolves #N`. If none, STOP with `validate-fix STOPPED: no issue reference`.
3. **For each referenced issue:**
   - **Pull the issue body.** `gh issue view <n> --json title,body,labels`.
   - **Find the `### Reproduction` block.** If missing, STOP for that issue with `needs-clarification: issue body has no reproduction`.
   - **Find the `### Test additions required` / `### Suggested fix` block.** Extract specific test names if listed.
4. **Check out the PR base.** `git fetch origin <baseRefName> && git checkout <baseRefName>`.
5. **Run the pre-patch reproduction** for each issue. Assert each fails (i.e., the bug exists). If any reproduction can't be run on the base, mark that issue `needs-clarification` and continue.
6. **Run the full pre-patch test suite** to capture the baseline. Save the pass/fail set.
7. **Check out the PR HEAD.** `git fetch origin <headRefName> && git checkout <headRefName>`.
8. **Run the patched-state reproduction** for each issue. Assert each now succeeds.
9. **Verify required regression tests are present.** For each test name extracted in step 3, assert it exists in the diff (`gh pr diff <n>` should contain the test name) and it passes when run individually.
10. **Run the full patched-state test suite.** Compare against step 6's baseline.
    - Any pre-patch-passing test now failing → regression → automatic `failed`.
    - All pre-patch-passing tests still passing AND patched-state-only-passing tests passing → no regression.
11. **Delegate to `run-quality-gates`** for Question 1 (lint, mypy, coverage, bandit, pip-audit, deptry, reuse, semgrep).
12. **Compose the verdict** using the output format below. Per issue.
13. **Post the PR comment + apply the label.** See "Where to record validations" below.

## Verdicts

| Verdict | Meaning |
|---|---|
| `validated` | Question 1 (gates) PASS + Question 2 (issue resolution) PASS for every referenced issue |
| `partial` | Question 1 PASS, but at least one issue's resolution check is missing or incomplete (e.g., regression test not added even though the issue called for one) |
| `failed` | Question 1 FAIL, OR Question 2's regression check found a previously-passing test now failing, OR patched-state reproduction still produces the bug |
| `needs-clarification` | Pre-patch reproduction couldn't run for at least one issue (missing fixture, ambiguous expected behavior, network-dependent). Maintainer must clarify before re-validation. |
| `needs-rerun` | Transient infrastructure failure (network blip during a live test, CI runner died). Not a code-quality verdict; just a "try again." |

## Output format

Produce this exact structure for each validation run.

```
## Validation: PR #<n> — <PR title>

### Verdict
<validated | partial | failed | needs-clarification | needs-rerun>

### Question 1: gates
<delegated to run-quality-gates — embed the structured output here>

### Question 2: issue resolution

#### Issue #<N1>: <title>
- Pre-patch reproduction: PASS / FAIL / NOT_RUN — <one-line reason>
- Patched-state reproduction: PASS / FAIL / NOT_RUN — <one-line reason>
- Required regression test(s): <list, with present/missing/passing/failing per test>
- No regression: PASS / FAIL — <count of tests that went red>

#### Issue #<N2>: <title>
... (same shape as N1)

### Summary
- Issues fully validated: [#<N1>, #<N2>]
- Issues with concerns: [#<N3>: <one-line concern>]
- Tests added in PR: [<test names>]
- Tests regressed: [<list>] (empty if none)

### Recommendation
<one of:>
- Merge — all checks pass, fix is mechanically sound.
- Hold — Question 2 partial; <what's missing>.
- Block — regression introduced OR fix doesn't resolve <issue>; <one-line action>.
- Re-run — transient failure; re-invoke validate-fix.

### Advisory (optional, non-blocking)
If the bug fits a recognizable class — `stale-stream-capture`, `parser-input-truncation`, `silent-fallback-without-log`, `validation-at-wrong-layer`, `signal-rc-collision`, `frozen-model-implicit-dep` — note the class here and suggest a property test that exercises the class, not just this instance. The fix may be mechanically correct AND leave the same bug class lurking in another module (e.g. `stale-stream-capture` recurs anywhere a module snapshots `sys.stdout`/`stderr` at import time). This is advisory only — does NOT change the verdict, does NOT block the merge. Bug-class taxonomy is informal; if no class fits, omit this section.
```

End with the standard signature block (matches `python-oss-crypto-reviewer`):

```
---
**Role:** Validator
**Reviewer:** Claude (validate-fix skill)
**Session:** <session-id>
**Round:** <N>
**Date:** YYYY-MM-DD
```

## Comment header

Every validation comment opens with this HTML header for machine parseability + multi-validator hygiene:

```
<!-- validate-fix:
  validator: claude-opus-4-7
  session: <short-id>
  round: <N>
  verdict: <validated | partial | failed | needs-clarification | needs-rerun>
  pr: <PR number>
  issues: [<comma-separated issue refs>]
  base-commit: <SHA>
  head-commit: <SHA>
  addresses-comment-id: <none | gh-comment-id of prior validation>
  ts: <ISO 8601>
-->
```

`addresses-comment-id` is required if a prior `validate-fix` comment exists on this PR. The label swap (changing `validation:claude:<old-verdict>` → `<new-verdict>`) must happen ONLY after the new comment is posted with `addresses-comment-id` naming the prior validation. Single transaction: comment first, then label.

## Where to record validations

GitHub PR comments, not issue comments. Validations live on the PR being validated.

```bash
# 1. Post the validation as a PR comment in the structured format above
gh pr comment <n> --repo paul007ex/qureddy --body-file /tmp/validation.md

# 2. Apply the matching label
gh pr edit <n> --repo paul007ex/qureddy --add-label "validation:claude:<verdict>"
```

If the labels don't exist on the repo yet, create them:

```bash
gh label create "validation:claude:validated" --repo paul007ex/qureddy --color "0e8a16" --description "Validate-fix verdict: VALIDATED"
gh label create "validation:claude:partial" --repo paul007ex/qureddy --color "fbca04" --description "Validate-fix verdict: PARTIAL"
gh label create "validation:claude:failed" --repo paul007ex/qureddy --color "b60205" --description "Validate-fix verdict: FAILED"
gh label create "validation:claude:needs-clarification" --repo paul007ex/qureddy --color "5319e7" --description "Validate-fix: needs maintainer clarification"
gh label create "validation:claude:needs-rerun" --repo paul007ex/qureddy --color "cccccc" --description "Validate-fix: transient failure, re-invoke"
```

When swapping a label (e.g. `failed` → `validated` after the author pushed a fix), use:

```bash
gh pr edit <n> --remove-label "validation:claude:failed" --add-label "validation:claude:validated"
```

## Failure modes this skill is designed to prevent

These are real patterns the skill blocks. Each rule above maps to one:

- "Tests pass, looks good to me" without checking the bug is reproducible → §3 + Question 2's pre-patch reproduction.
- "I refactored the test, now it passes" (the patch silently rewrote the test instead of fixing the bug) → §1 read-only + step 9 verifies the regression test exists in the diff.
- "Tests pass, but a different test broke" → step 10 baseline diff catches regressions.
- "I'll skip the pre-patch repro because it's hard to set up" → §5 hard-required.
- "I disagree with the reviewer but the gates pass anyway" → §7 disagreement window + §4 validate-on-merits (the reviewer's call is not the validator's call to override, but the validator also doesn't enforce the reviewer's call).
- "I patched the test to make it pass" → step 6 baseline + step 10 regression check show the test was previously passing or absent; a "fix" that modifies a test without fixing source code is suspicious.
- Multiple parallel validators stomping on each other's labels → §6 append-only + comment header `addresses-comment-id`.

## Interaction with other skills

| Skill | Relationship |
|---|---|
| `surgical-fix` | Authored the fix; this skill validates it. The validator NEVER becomes the author — if a fix is incomplete, the verdict reports it; `surgical-fix` (or the human) addresses it. |
| `python-oss-crypto-reviewer` | Reviews the fix's *approach*; this skill validates the fix's *result*. Both can run in parallel on the same PR — different signals, different verdicts. The validator must NOT validate during an active reviewer disagreement (§7). |
| `run-quality-gates` | Delegated for Question 1. The validator does not re-implement gate-running; it consumes the structured output. |
| `audit-pr` | Pre-merge final-review skill; can call this skill as one of its checks. The validator does not call `audit-pr`. |
| `mvp-implement` | If validation reveals the fix is incomplete/wrong, the next iteration may go through `mvp-implement` (or `surgical-fix`) — but that's a follow-up cycle, not part of this skill. |

## Self-check before producing the verdict

Walk this list before posting:

1. Is the PR not-a-draft? Mergeable? Has issue refs?
2. Did I run the pre-patch reproduction (or correctly mark it `needs-clarification`)?
3. Did I run the patched-state reproduction?
4. Did I capture the pre-patch test baseline?
5. Did I compare the patched-state suite against the baseline (regression check)?
6. Did I delegate to `run-quality-gates` for the Tier 1 sweep?
7. Did I produce a per-issue verdict, not a single global verdict?
8. Did I include the comment header with `addresses-comment-id` if there's a prior validation?
9. Did I touch any code? (If yes, I broke §1 — abort and post `needs-rerun`.)

If any answer is no, the verdict is invalid. Re-run the missing step.
