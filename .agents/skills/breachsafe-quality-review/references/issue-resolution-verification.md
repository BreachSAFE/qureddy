# Issue-resolution verification (Mode 3)

The sharpest framing in the source material for this skill: **"tests pass" and "the
issue is resolved" are different questions.** CI answers the first. This mode answers
the second. A PR can have every gate green and still miss the root cause, miss the
regression test the issue called for, or fix something adjacent to — but not the same
as — what the issue actually described.

This mode is read-only. It never modifies code. If it finds the fix incomplete, it
reports that — it does not attempt to complete the fix itself.

## When to run this

- A PR or patch claims to close/fix/resolve a specific tracked issue.
- Someone wants a verdict on "is this actually fixed" beyond "does CI say green."
- Post-merge spot-check: pull recently merged PRs, verify each claim against its issue.

## When not to run this

- No issue reference exists for the change. This mode needs an issue's description of
  expected behavior to validate against — without one there's no contract to check the
  fix against. Ask for one instead of guessing at intent.
- The change is a draft / work in progress. Wait until it's presented as done.
- You're being asked whether the *approach* was the right one (Option A vs Option B,
  architecture, design tradeoffs). That's a design-review question, not a mechanical
  resolution question — flag it back to the PR conversation rather than answering it
  here. This mode validates whether the chosen approach works, not whether it was the
  right approach to choose.

## Two questions, in order

### Question 1 — Are the gates green?

Delegate to the fast local check (`rust-quality-gates.md` / `python-quality-gates.md`).
Full suite, no filters, no skipped tests. This is necessary but does not, by itself,
answer Question 2.

### Question 2 — Is the issue actually resolved?

Four sub-checks:

1. **Pre-patch reproduction.** Check out the commit immediately before the patch. Run
   whatever reproduction steps the issue describes (a failing test, a repro script, a
   specific command + expected-vs-actual). Confirm it actually fails / reproduces the
   bug on that commit. If it doesn't, the bug isn't present on the base you're comparing
   against — the PR can't be validated as "fixing" something that wasn't there; stop and
   flag `needs-clarification`.

   This step is hard-required, not optional. Skipping straight to "run the patched state
   and see if it passes" proves nothing — a test that passes on both the base and the
   patch was never testing the bug.

2. **Patched-state reproduction.** Check out the patch. Re-run the same reproduction.
   Confirm it now succeeds (or the previously-wrong behavior is now correct).

3. **Required regression test present.** If the issue specifies what test coverage is
   required, confirm that test exists in the diff and passes when run individually — not
   folded into a broader test that happens to also cover it incidentally.

4. **No regression introduced.** Compare the full pre-patch test outcome set against the
   full patched-state outcome set. Any test that was passing before and is failing now is
   an automatic fail on this sub-check, regardless of what the issue asked for.

## Verdicts

| Verdict | Meaning |
|---|---|
| `validated` | Gates green AND all four sub-checks of Question 2 pass |
| `partial` | Gates green, but a sub-check is missing or incomplete (e.g. no regression test even though one was called for) |
| `failed` | Gates red, OR a regression was introduced, OR the patched-state reproduction still shows the bug |
| `needs-clarification` | Pre-patch reproduction couldn't be run (missing fixture, ambiguous expected behavior, environment-dependent) — a maintainer needs to supply a reproducible repro or explicitly accept "trust the patched-state behavior" as a maintainer call, not this skill's call |
| `needs-rerun` | A transient infrastructure failure (network blip, flaky runner), not a code-quality signal — just try again |

## Output format

```
## Validation: <PR / patch identifier>

### Verdict
<validated | partial | failed | needs-clarification | needs-rerun>

### Question 1: gates
<embed the quality-gates output>

### Question 2: issue resolution
- Pre-patch reproduction: PASS / FAIL / NOT_RUN — <reason>
- Patched-state reproduction: PASS / FAIL / NOT_RUN — <reason>
- Required regression test(s): <present/missing, passing/failing, per test>
- No regression: PASS / FAIL — <count of tests that went from green to red>

### Recommendation
Merge — all checks pass, fix is mechanically sound.
Hold — Question 2 partial; <what's missing>.
Block — regression introduced OR issue not actually resolved; <one-line reason>.
Re-run — transient failure.
```

## Common failure modes this mode exists to catch

- "Tests pass, looks good" without ever checking the bug was reproducible in the first
  place.
- The patch quietly rewrote or loosened the test instead of fixing the underlying code —
  caught by confirming the regression test is genuinely new/modified in the diff and
  actually exercises the described bug, not just that *a* test passes.
- "Tests pass, but a different test broke" — caught by the full before/after comparison,
  not a targeted re-run of just the changed area.
- Skipping the pre-patch repro because it's inconvenient to set up — this is exactly the
  shortcut that makes "tests pass" indistinguishable from "nothing was ever broken."

## Hard rules

- Never touch code. If a fix is genuinely needed, say so and hand it back — this mode
  reports, it does not patch.
- Validate one change at a time. Bundling multiple PRs into one verdict obscures which
  change caused which outcome.
- Don't skip the pre-patch reproduction step and call the result `validated`. Without
  proof the bug existed before the patch, a passing patched-state test is not evidence of
  anything.
- Any comment/label posted as part of this mode's output (per the top-level skill's
  authorization gate) requires explicit user authorization first — this mode can compose
  the verdict text freely, but does not post it to an issue tracker on its own initiative.
