# Current Milestone

The active implementation authority for MVP 0.1 is the skill:

**`.claude/skills/mvp-implement/SKILL.md`**

Claude Code loads this skill when the active task matches its scope (TLS scanner work, MVP 0.1 implementation, retry feature, output adapters, etc.). The skill is self-contained — it includes the model definitions, build order, scope rules, and quality gates.

## Historical reference

The earlier monolithic prompt is no longer in the public tree — the skill replaced it. The skill is now self-contained and canonical for everything MVP 0.1 needs (use cases, locked Pydantic models, locked policy model, JSON shape, retry semantics, build order). If you need the original verbose prompt for historical inspection, it lives at `scratch/MVP-0.1-CLAUDE-PROMPT.md` (gitignored, local only).

## When a milestone completes

Move the milestone's skill from `.claude/skills/mvp-implement/` to `.claude/skills/done/mvp-0.1/` and create a new `.claude/skills/mvp-implement/` for the next milestone. Update this file to point at the new skill. Do not let it drift.

## Bootstrap prompt for a fresh Claude session

`docs/mvp/MVP-0.1-BOOTSTRAP-PROMPT.md` provides the pasteable session bootstrap. It tells Claude to read the contracts, then load the skill, then begin work.
