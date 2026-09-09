<!--
SPDX-FileCopyrightText: 2026 BreachSAFE
SPDX-License-Identifier: Apache-2.0
-->

# QuReddy agent fast path

This file is the compact operating card for coding agents. Read `CLAUDE.md` for
the complete policy; this file intentionally avoids restating it.

## Contents

1. [Non-negotiable context](#non-negotiable-context)
2. [Ten-step change loop](#ten-step-change-loop)
3. [Fast command card](#fast-command-card)
4. [Output conformance](#output-conformance)
5. [Handoff format](#handoff-format)

## Non-negotiable context

- Canonical repository: `github.com/BreachSAFE/qureddy`.
- Python baseline: 3.14+; use `uv run --locked` for project commands.
- Release index: TestPyPI only. Production PyPI is out of scope.
- Existing repository license is Apache-2.0; preserve it unless a maintainer makes
  an explicit licensing decision.
- Keep SSH acquisition/`ssh-audit` migration parked in the 0.5.0 backlog.
- Do not infer that a green command ran all checks. Record commands and exit codes.
- Code comments and docstrings must preserve reviewer/agent context; follow the
  [commenting contract](docs/contributors/coding-rules.md#section-10--comments-and-docstrings).
- One PR at a time: never stack dependent PRs; rebase the next worktree only after
  merge and `origin/main` verification.
- During active work, re-check issues, PR feedback, CI/merge state, HITL, and other-agent
  findings after major steps and long-running jobs; record unrun checks as `NOT RUN`.

## Ten-step change loop

1. Inventory the issue, current tree, local guidance, applicable skills, and current
   issue/PR comments or reviewer feedback.
2. Steelman the problem and the smallest defensible fix.
3. Reproduce the current behavior in an isolated `/tmp` workstream first.
4. Pressure-test alternatives, malformed input, compatibility, and regressions.
5. Implement the smallest surgical change in a focused worktree.
6. Add or update regression tests that fail before the fix.
7. Run the project gates and record real exit codes.
8. Run the anti-pattern/architecture self-check, review all current PR feedback,
   and resolve, test, or explicitly defer every actionable comment.
9. Update the issue/PR with evidence and comment resolutions, commit, push, and
   open/merge only with explicit authorization.
10. For a release, verify the package, image, and real CLI smoke path separately.

If a step is not run, report `NOT RUN` and why. Never replace an isolated
reproduction with a patched-state test.

Review feedback is a required loop, not a final courtesy: read it before coding,
re-check it after local gates, and re-read it immediately before merge. A PR is
not ready while an actionable reviewer comment is unanswered, untested, or
silently deferred.

## Fast command card

```bash
cd <repo-root>
uv sync --locked --extra dev
uv run --locked pytest tests/test_<area>.py -q
just gates
just hooks
just docs
just release-gate
```

Use `just test-unit` for a quick local loop and `just gates` before handoff.
Use `just test-live` only when network access is intentional. For a temporary
workstream, copy the candidate tree into a fresh `/tmp/qureddy-<issue>-*`
directory, run the same locked commands there, and preserve its logs.

## Output conformance

The CLI's bundle mode renders one canonical scan into the four supported output
surfaces: `scan.json`, `scan.jsonl`, `scan.cdx.json` (CycloneDX 1.7 CBOM), and
`scan.rich.txt`. Validate that bundle with:

```bash
uv run --locked python scripts/validate_output_bundle.py \
  --run-dir <bundle-dir> --scanner <tls|ssh|ike> --target <original-target>
```

For live TLS, SSH, and IKE coverage, run the existing multi-endpoint harness:

```bash
QUREDDY_KEEP_SMOKE_ARTIFACTS=1 scripts/smoke_cbom_live.sh
```

It must be run intentionally with network access and reports the real CLI exit
code for every target. `scripts/validate_output_bundle.py` validates JSON and
JSONL correlation, required Rich sections and finding values, and the pinned
CycloneDX schema/semantic contract. SARIF is not a QuReddy output format yet;
do not report SARIF as covered until a renderer and schema gate are added.

Every PR touching output or scanner behavior must include the targeted tests,
`just gates`, and the live bundle harness when network access is available. A
green unit suite alone is not evidence that all output surfaces stayed aligned.

## Handoff format

End each milestone with only:

```text
State: <clean|dirty>; commit/tag: <value>
Changed: <files and one-line purpose>
Evidence: <commands with pass/fail and key counts>
Open: <issue IDs or NOT RUN items>
Next: <one concrete action>
```

Do not paste entire source files or repeated command output unless the user asks
for a specific excerpt. Link to files and quote only the relevant lines.
