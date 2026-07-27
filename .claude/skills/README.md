# Claude Code Skills for QuReddy

This directory contains skills that Claude Code agents invoke when working on QuReddy. Each subdirectory is a single skill with a focused workflow.

Skills are **lazily loaded**: the agent reads each skill's description (the YAML frontmatter and the first paragraph), decides which apply to the current task, then loads only those skills' full content. This keeps context tight while making complex workflows reproducible.

## Available skills

| Skill | When the agent invokes it |
|---|---|
| `mvp-implement` | Implementing or extending MVP 0.1 (TLS scanner). Self-contained operational authority for the current milestone. |
| `surgical-fix` | Fixing one Python bug, regression, failing test, parser/CLI/output/subprocess defect, or security-sensitive behavior issue with a narrow test-first patch and anti-pattern audit. |
| `audit-pr` | Before opening or finalizing a pull request. Walks the diff against `docs/contributors/coding-rules.md` and produces the PR-template output. |
| `write-test-fixture` | Adding a new captured OpenSSL fixture under `tests/fixtures/openssl/`. |
| `run-quality-gates` | Pre-final-response check on any code-touching task. Runs the Tier 1 enterprise-grade gates (ruff, mypy, pytest+coverage, bandit, pip-audit, deptry, reuse, semgrep, secret scan) and produces structured PASS/FAIL/NOT RUN output. |
| `python-oss-crypto-reviewer` | Reviewing a proposed bug fix, PR diff, or another agent's code suggestion. Produces APPROVE / APPROVE WITH CHANGES / REJECT verdict against correctness, security, and schema-stability standards. |
| `validate-fix` | Verifying a single PR actually resolves the GitHub issue(s) it claims to fix. Read-only on the PR diff. Distinguishes "tests pass" from "issue resolved" — applies a `validation:claude:<verdict>` label. |
| `audit-docs` | Auditing the doc surface for drift against the working tree. Four classes: runnable examples (Class A), ADR status freshness (Class B), cross-reference integrity (Class C), cross-doc consistency for canonical contracts (Class D). Read-only — produces a findings report. |
| `breachsafe-implement` | Implementing narrowly scoped BreachSAFE Python or Rust work with test-first quality gates. |
| `breachsafe-pqc-pm` | Sequencing and reconciling product work across the BreachSAFE Quantum Platform. |
| `breachsafe-quality-review` | Reviewing code, pull requests, issue resolution, and documentation truth without mutating the reviewed work. |
| `breachsafe-release` | Auditing supply-chain and OSS release readiness, including whether configured gates actually block. |
| `breachsafe-security-audit` | Performing a deep security and cryptographic-correctness audit. |

## For human contributors

You don't need to invoke skills directly. Project documentation lives in `docs/`. Read `CLAUDE.md` for project orientation, `docs/contributors/coding-rules.md` for the engineering standards.

## For AI agents

Read the skill's `SKILL.md` before starting any task that matches the skill's scope. The skill content is the operational form of the rules in `docs/contributors/coding-rules.md`. When skills and `docs/contributors/coding-rules.md` disagree, `docs/contributors/coding-rules.md` wins and the skill needs updating.
