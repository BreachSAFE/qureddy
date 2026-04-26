<!-- SPDX-License-Identifier: Apache-2.0 -->

## Summary

<!-- One paragraph describing what this PR does and why. -->

## Type of change

<!-- Check exactly one. Per CODING_RULES Rule 1.3, one thing per PR. -->

- [ ] feat — new feature
- [ ] fix — bug fix
- [ ] docs — documentation only
- [ ] test — test changes only
- [ ] refactor — internal restructure, no behavior change
- [ ] build — build/dependency change
- [ ] ci — CI/workflow change
- [ ] chore — other maintenance
- [ ] perf — performance improvement
- [ ] security — security fix or hardening

## Related issue

<!-- Link to the issue this PR addresses. If none, explain why. -->

Fixes #

## Decisions made

<!-- Per the audit-pr skill: list every micro-decision a future maintainer would
     ask "why did they do that?" about. One line each. Examples:
     - Chose tuple over list for ScanTarget.dependencies because models are frozen
     - Used freezegun rather than monkeypatching datetime because cleaner under retries
     - Did not extract helper for sni-resolution; only one call site
-->

-

## Audit checklist

This is the **Tier 1 PR audit** from `docs/contributors/coding-rules.md` Quick Reference. Do not skim. Every box must be honestly checked or the PR is not ready.

### Scope

- [ ] One thing per PR (Rule 1.3)
- [ ] Mechanical formatting changes are in a separate commit from behavior changes (Rule 1.5)
- [ ] No out-of-scope work bundled in (Rule 1.1)

### Code

- [ ] No file over 400 lines
- [ ] No function over 50 lines (30 line norm)
- [ ] No class over 200 lines
- [ ] Every public function has a Google-style docstring
- [ ] Every Pydantic model is frozen with `extra="forbid"` unless explicitly mutable
- [ ] All collections are `tuple[X, ...]` unless mutation is required
- [ ] All datetimes are timezone-aware UTC
- [ ] No `print()` in library code (only output adapters and CLI write to stdout)

### Quality gates (Tier 1, every PR)

<!-- Run `just gates` or run each command manually. State PASS / FAIL / NOT RUN with reason. -->

- [ ] `ruff check .` — PASS / FAIL / NOT RUN:
- [ ] `ruff format --check .` — PASS / FAIL / NOT RUN:
- [ ] `mypy src/qureddy --strict` — PASS / FAIL / NOT RUN:
- [ ] `pytest --cov=qureddy --cov-fail-under=80` — PASS / FAIL / NOT RUN: (N tests, X% coverage)
- [ ] `bandit -r src/qureddy` (MEDIUM threshold) — PASS / FAIL / NOT RUN:
- [ ] Secret scan (`gitleaks` or `trufflehog`) — PASS / FAIL / NOT RUN:

### Tests

- [ ] Every new function with non-trivial logic has at least one test
- [ ] Error paths and boundary values are tested, not just happy paths
- [ ] No new `@pytest.mark.skip`, `@pytest.mark.acceptance`, or `tests/integration/` carve-outs
- [ ] Fixtures under `tests/fixtures/` use real captured outputs (no synthetic stubs without comment justification)
- [ ] Live tests pass on local network OR transient failure documented
- [ ] (MVP 0.1 scanner code only) Use case coverage from `.claude/skills/mvp-implement/SKILL.md` checked

### Security bar (`docs/contributors/coding-rules.md` §26 — hard merge blockers)

- [ ] No `verify=False` or `ssl.CERT_NONE` introduced
- [ ] No `shell=True` introduced
- [ ] No `eval`, `exec`, or `pickle.loads` on untrusted input
- [ ] No logging of secrets, full PEMs, full traces, or full subprocess output
- [ ] User-supplied paths use `pathlib.Path.resolve()` and are validated
- [ ] Subprocess calls have explicit `timeout`, list-form args, `shell=False`
- [ ] OpenSSL subprocess calls live only in `src/qureddy/scanners/tls/openssl_probe.py`
- [ ] No `random` for security-sensitive randomness (use `secrets`)
- [ ] No insecure shortcut accepted on request (Rule 26.13)

### Anti-pattern audit

- [ ] Audited against `docs/contributors/agent-antipatterns.md`. Result:

  - [ ] No violations
  - [ ] Violations accepted (list each as `ANTIPATTERN ACCEPTED: <name>, because <reason>`)

  Accepted antipatterns:
  -

### Documentation

- [ ] `CHANGELOG.md` updated under `[Unreleased]` if this PR changes user-visible behavior
- [ ] Internal documentation links verified (point at real files / real anchors)
- [ ] No commented-out code, no floating TODOs without `# TODO(reason): description`

### Dependencies

<!-- Only relevant if pyproject.toml or uv.lock changed. -->

- [ ] Every new dependency justified per Rule 13.1 (replaces ≥50 lines, actively maintained, Apache-compatible license, recognizable maintainer)
- [ ] No GPL, AGPL, or LGPL dependencies introduced
- [ ] `pip-audit` passes (no HIGH or CRITICAL CVEs in dep tree) — PASS / FAIL / NOT RUN:
- [ ] `pip-licenses` passes (no AGPL/GPL/LGPL) — PASS / FAIL / NOT RUN:
- [ ] `deptry .` passes (no unused or missing deps) — PASS / FAIL / NOT RUN:

### Security exceptions

<!-- Only if any security rule is being waived. Permanent exceptions are forbidden. -->

- [ ] No security exception in this PR
- [ ] Security exception accepted, documented as `SECURITY EXCEPTION ACCEPTED: <rule>, because <reason>, expires <date or issue>` and tracked in `docs/SECURITY_EXCEPTIONS.md`

## Reviewer notes

<!-- Anything you want the reviewer to focus on. Out-of-scope flags. Open questions. -->

-

---

By submitting this PR I confirm:

- [ ] I read `CONTRIBUTING.md` and `docs/contributors/coding-rules.md` before writing this code
- [ ] I am the author of this code, or it is sourced and licensed compatibly with Apache 2.0
- [ ] I agree to the [Code of Conduct](../CODE_OF_CONDUCT.md)
