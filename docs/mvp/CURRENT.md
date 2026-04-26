# Current Milestone

The active milestone implementation prompt is:

**`docs/mvp/MVP-0.1-CLAUDE-PROMPT.md`**

When a milestone completes, move its prompt and any milestone-specific notes to `docs/mvp/done/<version>/` and update this file to point at the new active milestone. Agents and humans both read this file to find the live prompt; do not let it drift.

## Bootstrap prompt

For a fresh Claude Code session that needs to absorb the contracts before reading the milestone prompt, paste `docs/mvp/MVP-0.1-BOOTSTRAP-PROMPT.md` into the session.
