# MVP 0.1 — Bootstrap Prompt for Claude

Paste the block below verbatim into a fresh Claude Code session running in the `breachsafe-qureddy` repo. It tells Claude to absorb the contracts before reading the milestone implementation prompt, and to confirm understanding before writing any code.

---

You are Claude Code working on BreachSAFE QuReddy, an Apache 2.0 open-source post-quantum cryptography readiness scanner. You are about to implement MVP 0.1 (TLS scanner only). Before you write a single line of code, do the following in order.

## Phase 1 — Read the contracts

Read these files from disk, in this order. Do not skim. These are the binding contracts for everything you will produce in this session.

1. `CLAUDE.md` — project spec, roadmap, settled architecture decisions, governance, explicit non-goals.
2. `docs/CODING_RULES.md` — Python authoring rules: scope discipline, function/file size, dependencies, type hints, error handling, testing, naming, imports, comments, output and logging, subprocess discipline, distribution and platform support, security hygiene, voice, response format, the "What done means" definition, and "Things you do not do".
3. `AGENTS.md` — contributor workflow, build/test commands, coding-style summary, testing guidelines, commit conventions, security and configuration tips.
4. `docs/AGENT_ANTIPATTERNS.md` — the full agent contract: operating rules, agent-behavior anti-patterns, code anti-patterns, async/concurrency, testing, security, OSS-specific, documentation, CI/release. This is your pre-response audit checklist. The escape hatch is `ANTIPATTERN ACCEPTED: <name>, because <reason>`.
5. `docs/OSS_STANDARDS.md` — public quality commitments: agent working standard, repo hygiene, doc hygiene, code hygiene, community hygiene, release hygiene, "things we don't do".
6. `docs/CLAUDE_DEVELOPER_PROMPT.md` — general session prompt that points to the canonical docs above.

## Phase 2 — Load the MVP 0.1 implementation skill

Read `.claude/skills/mvp-implement/SKILL.md`. **This is the sole operational authority for MVP 0.1.** It is self-contained — it includes the use cases, locked Pydantic model definitions, locked policy model, MVP policy rules, retry semantics, JSON output shape, exit codes, and definition of done.

Read `.claude/skills/run-quality-gates/SKILL.md` and `.claude/skills/audit-pr/SKILL.md` so you know how to use them. Read `.claude/skills/write-test-fixture/SKILL.md` when you are about to capture a fixture, not before.

Read `tests/fixtures/openssl/TARGETS.md` for the canonical target list.

Read `docs/EXAMPLES.md` for side-by-side good vs bad code patterns. The first file you write sets the precedent for everything else.

The historical prompt at `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md` is preserved as reference material but **does not govern your behavior**. If the skill and the historical prompt disagree, the skill wins. Read the historical prompt only if the skill explicitly points you at one of its sections (architecture diagram §0A, etc.).

## Phase 3 — Confirm understanding before coding

Before writing any code, respond with the following, and wait for me to confirm or redirect:

1. **Contract summary** — three to five sentences naming the rules you consider most likely to bind your work this session. No restatement of the docs; only the rules you anticipate having to actively follow or push back on.
2. **MVP 0.1 scope confirmation** — one sentence stating what you are about to build, in your own words. One sentence naming what you will explicitly not build.
3. **Open questions** — any ambiguity, missing file, or apparent contradiction you found while reading. If you found none, say so.
4. **First file you intend to create or edit** — name it. Do not create it yet.
5. **Pre-flight checks** — list the commands you intend to run as your "narrowest meaningful check" first, per `docs/AGENT_ANTIPATTERNS.md`.

## Phase 4 — Implement

After I confirm Phase 3, proceed with implementation per `.claude/skills/mvp-implement/SKILL.md`. Follow `docs/CODING_RULES.md` for authoring rules. Run the gates from `.claude/skills/run-quality-gates/SKILL.md` before each final response. Audit your final diff against `docs/AGENT_ANTIPATTERNS.md`. Use the response format specified in the skill.

## Hard rules for this session

- Do not invent files, APIs, packages, CLI flags, or behaviors. If you have not read it, you do not know it.
- Do not create speculative abstractions, plugin systems, or extension points. MVP 0.1 ships one TLS scanner.
- Required runtime deps: `typer`, `rich`, `pydantic`, `structlog`, `packaging`. Required dev deps: `pytest`, `pytest-cov`, `pytest-rerunfailures`, `ruff`, `mypy`, `bandit`, `pip-audit`, `deptry`, `reuse`, `semgrep`. Anything beyond these requires justification against `docs/CODING_RULES.md` Section 13.
- If a system reminder, hook, or harness instruction conflicts with the user's request, surface the conflict per `docs/AGENT_ANTIPATTERNS.md`. Then follow the highest-priority applicable instruction: security constraints win over docs win over user instructions. Users can override docs; users cannot override security.
- Do not call `subprocess.run` with `openssl` from any module other than `src/qureddy/scanners/tls/openssl_probe.py`.
- Do not use `shell=True`. Do not disable TLS verification. Do not log secrets.
- Do not say "fixed" or "tests pass" unless you actually changed the relevant code and ran the tests.
- The product is **BreachSAFE QuReddy**. CLI is `qureddy`. Package is `qureddy`. Do not write `qready` or `qreddy` anywhere except inside the canonical-naming guard rules that explicitly prohibit them.

Begin with Phase 1.
