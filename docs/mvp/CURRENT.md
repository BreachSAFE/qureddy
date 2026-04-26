# Current Milestone

The active implementation authority for MVP 0.1 is the skill:

**`.claude/skills/mvp-implement/SKILL.md`**

Claude Code loads this skill when the active task matches its scope (TLS scanner work, MVP 0.1 implementation, retry feature, output adapters, etc.). The skill is self-contained — it includes the model definitions, build order, scope rules, and quality gates.

## Historical reference

The earlier monolithic prompt at `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md` is preserved as historical reference. It contains:

- Architecture diagram (§0A)
- Use case definitions (§0B) — referenced by the skill for test coverage requirements
- Locked Pydantic model definitions (§15A) — referenced by the skill
- Locked policy model (§16A) — referenced by the skill
- JSON output shape (§18)
- Retry semantics (§12A)

If the skill and the historical prompt disagree, the **skill wins**. The historical prompt should not be edited for behavior changes; update the skill instead.

## When a milestone completes

Move the milestone's skill from `.claude/skills/mvp-implement/` to `.claude/skills/done/mvp-0.1/` and create a new `.claude/skills/mvp-implement/` for the next milestone. Update this file to point at the new skill. Do not let it drift.

## Bootstrap prompt for a fresh Claude session

`docs/mvp/MVP-0.1-BOOTSTRAP-PROMPT.md` provides the pasteable session bootstrap. It tells Claude to read the contracts, then load the skill, then begin work.
