---
name: breachsafe-release
description: Audit supply-chain posture (cargo audit/deny/vet for Rust, pip-audit/deptry/reuse-lint/gitleaks for Python) and OSS release-readiness (OpenSSF Scorecard, OSPS Baseline, Best Practices badge, crates.io/PyPI publish readiness, Trusted Publishing/OIDC, Sigstore/SLSA provenance) for a package or crate approaching release. Verifies gates are CI-ENFORCED, not just present as unused config. Audit only — never files issues, never publishes, never tags a release without explicit authorization.
---

# breachsafe-release

**Applies to:** QuCrypt, QuCert (Rust / crates.io) and QuReddy, Qurum (Python / PyPI) once
they approach a real release; QuCustody once it has code to release.

## Stop and read this first: authorization gate

This is the highest-blast-radius skill in this library: its whole domain is release and
publish actions, and a crates.io or PyPI publish is effectively irreversible (yanking still
leaves the version number and artifact permanently listed). Treat that as load-bearing.

This skill may run freely, without asking:
- read-only inspection: `git log`/`status`/`diff`, `gh` read commands, reading config files,
- checks that fail closed but don't act: `cargo audit`, `cargo deny check`, `cargo vet`,
  `pip-audit`, `deptry`, `reuse lint`, `gitleaks detect`, OpenSSF Scorecard's local proxies,
- **dry-run** publish checks: `cargo publish --dry-run`, `cargo package --list`,
  `twine check`, `uv build` followed by inspecting the built artifacts. These build and
  inspect; they do not upload anywhere.

It must **never**, on its own initiative:
- run a real publish (`cargo publish`, `twine upload`, `uv publish`, or triggering a
  configured release/publish CI workflow),
- create or push a release tag, cut a GitHub Release, or edit release notes as a published
  artifact,
- file or comment on a GitHub issue, open a PR, or change a label,
- edit repo config (`deny.toml`, `pyproject.toml`, CI workflow files) to "fix" a finding —
  this skill reports gaps, it does not remediate them.

It may **draft** issue text, a findings report, or a release checklist and show it to the
user. Nothing gets filed or executed until the user gives explicit, in-conversation
authorization for that specific action — "just publish it" for a specific version at the end
of a review counts as authorization for that one action, not a standing green light for
future runs.

## Stay in its lane

This skill covers supply-chain posture and release-readiness only. If the actual ask is one
of these, point at the right skill instead of doing it here:

- General code quality / PR correctness review → `breachsafe-quality-review`
- Crypto correctness / FIPS-RFC conformance → `breachsafe-security-audit` /
  `breachsafe-conformance`
- Writing or fixing code → `breachsafe-implement`
- Deciding what to build / sequencing → `breachsafe-pqc-pm`

## The two concerns this skill covers — they compose, they don't duplicate

1. **Supply-chain enforcement** — is the dependency tree scanned for known vulnerabilities,
   license problems, and provenance gaps, and is that scan actually wired into CI so a
   finding can **fail the build** — not just present as a tool someone ran once locally.
   Full checklist: `references/supply-chain-checklist.md` (Rust and Python sections).
2. **OSS release-readiness** — is the package/crate itself ready to publish per the current
   OpenSSF/OSPS bar and the target registry's own requirements (crates.io or PyPI).
   Full checklist: `references/oss-release-readiness-checklist.md`.

Release-readiness **defers to** the supply-chain checklist for the vulnerability-scan
criterion rather than re-running it — don't double-report the same `cargo audit` or
`pip-audit` finding under both headings.

## The recurring trap this skill exists to catch

A security tool that **runs** but cannot **fail the build** is theater: `cargo audit`
without `--deny warnings` exits 0 on findings; a `cargo-deny`/`pip-audit` config that silently
doesn't load enforces nothing; a gate that only lives in a local pre-commit hook (not CI) is
skippable by anyone who doesn't run it. Always check the FAIL path — the exit code and the CI
wiring — not just "the tool is installed and I ran it once."

One illustrative class of mistake, from this codebase family's own history: a `cargo-deny`
config file that was misnamed (a typo'd extension instead of exactly `deny.toml`) and so
silently fell back to cargo-deny's default config, enforcing nothing while looking configured.
That specific instance has since been fixed — verify the current state with
`ls deny.toml .cargo/deny.toml` rather than assuming either the bug or the fix — but the
underlying check ("is the config file named exactly what the tool expects, and does it
actually load?") is real and worth running every time, not a one-off historical footnote.

## Ecosystem dispatch

Detect which ecosystem(s) are in play before picking a checklist — don't assume Rust:

```bash
test -f Cargo.toml && echo "Rust crate — run the Rust supply-chain + crates.io sections"
test -f pyproject.toml && echo "Python package — run the Python supply-chain + PyPI sections"
```

A repo can be single-ecosystem (most of this family today) or, in principle, mixed (a Rust
core with a Python binding surface) — run both sections when both markers are present, and
say explicitly in the report which ecosystem each finding belongs to.

## How to run this skill

1. Detect ecosystem(s) as above.
2. Run the matching supply-chain checklist(s) — `references/supply-chain-checklist.md`.
   Verify enforcement (CI wiring, fail-closed flags), not just presence.
3. Run the OSS release-readiness checklist — `references/oss-release-readiness-checklist.md`
   — for each package/crate that is actually heading toward a publish. If nothing is
   imminently publishable, say so and skip straight to reporting current gaps as forward
   work rather than inventing urgency.
4. Report findings to the user as a plain checklist: met / gap / needs-repo-settings-check
   (some OpenSSF Scorecard checks need GitHub API access and can't be verified from a local
   checkout — say so rather than guessing).
5. If the user wants findings filed as issues, or wants an actual publish run, draft the
   exact command/content first and wait for explicit authorization — see the gate above.

## Honesty rules

- "Tool present" is not "tool enforcing." Always check the exit code and the CI YAML, not
  just that a config file exists.
- A clean scan today is point-in-time; the value this skill checks for is the recurring gate,
  not a single clean run.
- Distinguish findings that need the GitHub API (branch protection, signed releases) from
  ones verifiable locally — mark the former "needs repo-settings check," don't assume pass.
- Note real strengths alongside gaps (e.g. a clean `cargo audit`, a SECURITY.md with a real
  contact) — readiness review isn't only a list of problems.

## References

- `references/supply-chain-checklist.md` — cargo audit/deny/vet (Rust) and
  pip-audit/deptry/reuse-lint/gitleaks (Python), with the CI-enforcement checks for each.
- `references/oss-release-readiness-checklist.md` — OpenSSF Scorecard, OSPS Baseline, Best
  Practices badge, crates.io and PyPI publish readiness, Trusted Publishing/OIDC,
  Sigstore/SLSA provenance, REUSE/SPDX, and community-health-file checks.
