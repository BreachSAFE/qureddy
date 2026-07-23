# Python quality gates (Mode 1 — fast local check)

Applies to the Python components (QuReddy today; Qurum and any future Python tooling).
Run this before opening a PR, before a final response on any code-touching task, or
whenever asked "are we ready to merge."

Check the repo for a task runner (`justfile`, `Makefile`, `tox.ini`) that already wires
these together — e.g. a `just gates` target — and prefer that over re-typing each command,
as long as you can still verify each individual gate's exit code rather than trusting the
runner's overall pass/fail.

## Sequence

Run in order. Capture each command's exit code and a short (~5 line) excerpt of output.

1. **Lint** — `ruff check .` (or the repo's configured linter). Pass: exit 0.
2. **Format check, verify-only** — `ruff format --check .`. Pass: exit 0. Do **not** run
   the mutating form (`ruff format .`, no `--check`) in an audit context — formatting is a
   separate commit from a review/gate run.
3. **Type check** — `mypy <package> --strict` (or the repo's configured strictness). Pass:
   exit 0, no bare `Any`, no untyped public functions.
4. **Static security lint** — `bandit -r <package>`. Pass: 0 findings at MEDIUM or higher;
   report LOW findings without blocking on them.
5. **Dependency CVE scan** — `pip-audit`. Pass: 0 HIGH/CRITICAL. Investigate failures as
   real upstream disclosures rather than lowering the threshold.
6. **Dependency hygiene** — `deptry .` (declared-but-unused / used-but-undeclared
   dependencies). Pass: exit 0.
7. **License header compliance** — `reuse lint` (or equivalent). Pass: exit 0 — every
   source file has an SPDX header if the repo requires one.
8. **Broader static analysis (often report-only early on)** — `semgrep scan --config auto
   .`. Check the repo's own gate policy for whether this blocks yet; many projects start
   it report-only until the false-positive baseline is tuned. Never silence a finding in
   code without an explicit, reasoned suppression comment.
9. **Secret scan** — `gitleaks detect --no-git --source .` (or `trufflehog filesystem
   --no-update .` if that's what's installed). Pass: 0 verified secrets.
10. **Tests with coverage** — `pytest --cov=<package> --cov-fail-under=<threshold>`. Pass:
    exit 0, full suite (no `-k` filter, no skip markers), coverage at or above the repo's
    threshold. If a retry/rerun plugin is configured, a `Rerun:` marker means a transient
    failure was absorbed — note it, don't treat it as a failure, but also don't raise the
    retry count to mask a test that fails deterministically.
11. **Project-specific audit scripts**, if any exist (e.g. a phase/milestone verification
    script under `scripts/`). Run it if present; if it doesn't exist yet, say so rather
    than skipping silently.

## Hard rules

- Never write "PASS" for a gate you didn't actually run. Use "NOT RUN" with the reason
  (tool not installed, project not installable yet, etc.).
- Don't paraphrase tool output — quote the real exit code and a verbatim excerpt.
- Don't skip a gate because "it's probably fine." If it doesn't apply at this project
  stage, say so explicitly.
- For security-tier gates (static security lint at MEDIUM+, secret scan, dependency CVEs
  at HIGH+), the only acceptable resolution to a failure is fix-then-re-run — not lowering
  the threshold, not an exception baked into config without sign-off.

## Report format

```
## Quality Gates Result

| Gate | Command | Status | Notes |
|---|---|---|---|
| Lint | ... | PASS / FAIL / NOT RUN | |
| Format check | ... | PASS / FAIL / NOT RUN | |
| Type check | ... | PASS / FAIL / NOT RUN | |
| Static security | ... | PASS / FAIL / NOT RUN | threshold used |
| Dep CVEs | ... | PASS / FAIL / NOT RUN | threshold used |
| Dep hygiene | ... | PASS / FAIL / NOT RUN | |
| License headers | ... | PASS / FAIL / NOT RUN | |
| Broader static analysis | ... | PASS / FAIL / NOT RUN | blocking or report-only |
| Secret scan | ... | PASS / FAIL / NOT RUN | tool used |
| Tests + coverage | ... | PASS / FAIL / NOT RUN | N tests, X% coverage |
| Project audit script | ... | PASS / FAIL / NOT RUN / NOT PRESENT | |

**Summary:** all blocking gates PASS / N failed / N not run.
**Ready for merge:** YES / NO (reason)
```
