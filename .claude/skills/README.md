# Claude Code Skills for QuReddy

This directory contains skills that Claude Code agents invoke when working on QuReddy. Each subdirectory is a single skill with a focused workflow.

Skills are **lazily loaded**: the agent reads each skill's description (the YAML frontmatter and the first paragraph), decides which apply to the current task, then loads only those skills' full content. This keeps context tight while making complex workflows reproducible.

## Available skills

| Skill | When the agent invokes it |
|---|---|
| `mvp-implement` | Implementing or extending MVP 0.1 (TLS scanner). Authoritative spec for the current milestone. |
| `audit-pr` | Before opening or finalizing a pull request. Walks the diff against `docs/CODING_RULES.md` and produces the PR-template output. |
| `write-test-fixture` | Adding a new captured OpenSSL fixture under `tests/fixtures/openssl/`. |
| `self-scan` | Running QuReddy against its own canonical target list and capturing artifacts. |

## For human contributors

You don't need to invoke skills directly. Project documentation lives in `docs/`. Read `CLAUDE.md` for project orientation, `docs/CODING_RULES.md` for the engineering standards.

## For AI agents

Read the skill's `SKILL.md` before starting any task that matches the skill's scope. The skill content is the operational form of the rules in `docs/CODING_RULES.md`. When skills and `docs/CODING_RULES.md` disagree, `docs/CODING_RULES.md` wins and the skill needs updating.
