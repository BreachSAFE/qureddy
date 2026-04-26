# ADR 0002 — Adopt Diátaxis as the documentation standard

**Status:** Accepted
**Date:** 2026-04-26
**Deciders:** Paul Volosen, project lead
**Consulted:** Claude (review)
**Informed:** Codex
**Supersedes:** none
**Superseded by:** none

---

## Context

Documentation drifts as a project ships features. At MVP 0.1 the project already has docs in three places (`README.md`, `CONTRIBUTING.md`, `docs/`) plus governance files (`SECURITY.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`) plus agent contracts (`CLAUDE.md`, `AGENTS.md`, `docs/CLAUDE_DEVELOPER_PROMPT.md`).

Several existing docs already mix purposes — `SECURITY.md` is part reference (severity matrix) and part how-to (reporting steps); `OSS_STANDARDS.md` is part reference (the standards) and part explanation (why we adopt them); `AGENT_ANTIPATTERNS.md` is part reference (the rules) and part explanation (why each antipattern matters). Mixed-purpose docs are the documentation smell that scales worst — every reader has to skim past the parts they don't need.

The project will add user-facing content rapidly through MVP 0.2 (cert scanning), 0.3 (CBOM), 0.4 (SSH), 0.5 (config), 0.6 (source-code), and v1.0. Without a structural standard now, that content will land wherever the author thinks it fits, and the doc tree will be unrecoverable by v1.0 without a big rename PR that breaks every external link.

## Decision

**Adopt [Diátaxis](https://diataxis.fr) as the structural documentation standard for QuReddy, effective immediately.**

Diátaxis splits all documentation into exactly four quadrants based on what the reader is trying to do:

|  | Theoretical (concept) | Practical (action) |
|---|---|---|
| **Studying** (learning) | Explanation | Tutorials |
| **Working** (doing) | — | How-to guides and Reference |

Each quadrant answers a different reader question. Each page belongs to exactly one quadrant.

### Concretely for QuReddy

- `docs/tutorials/` — learning-oriented walkthroughs (e.g. "Your first scan")
- `docs/how-to/` — task-oriented recipes (e.g. "Scan an IP with custom SNI")
- `docs/reference/` — exhaustive lookup material (CLI options, exit codes, JSON schema)
- `docs/explanation/` — conceptual discussion (why hybrid PQ, what HNDL is, threat model)
- `docs/contributors/` — engineering rules + how-to for *contributors*, not end users
- `docs/contributors/adr/` — architectural decision records
- `docs/contributors/agents/` — agent role specifications and bootstrap prompts

### Editorial rules (mandatory)

These are enforceable in code review:

1. **One quadrant per page.** A page that mixes purposes gets split before the next change merges.
2. **Tutorials never reference; reference never explains.** Cross-linking is fine; content-mixing is not.
3. **How-to assumes familiarity.** Don't repeat introductory material — link to it.
4. **Reference is exhaustive, never opinionated.** "We recommend" goes in How-to.
5. **Explanation has no commands.** Worked examples belong in Tutorials or How-to.
6. **Front-load the answer.** Every page opens with what it covers in 1–2 sentences.
7. **No marketing voice.** This is technical documentation.

## Consequences

### What changes

- Existing `docs/` files are moved into the appropriate quadrant via `git mv` so blame is preserved:
  - `docs/CODING_RULES.md` → `docs/contributors/coding-rules.md`
  - `docs/AGENT_ANTIPATTERNS.md` → `docs/contributors/agent-antipatterns.md`
  - `docs/EXAMPLES.md` → `docs/contributors/examples.md`
  - `docs/OSS_STANDARDS.md` → `docs/contributors/oss-standards.md`
  - `docs/CLAUDE_DEVELOPER_PROMPT.md` → `docs/contributors/agents/claude-developer-prompt.md`
  - `docs/mvp/CURRENT.md` → `docs/reference/milestones.md`
  - `docs/mvp/MVP-0.1-BOOTSTRAP-PROMPT.md` → `docs/contributors/agents/mvp-0.1-bootstrap-prompt.md`
- A new `docs/README.md` declares the standard and lists what's in each quadrant.
- The README at the repo root gains a "Documentation" section pointing at the four quadrants.
- Mixed-purpose docs (`SECURITY.md`, `OSS_STANDARDS.md`, `AGENT_ANTIPATTERNS.md`) get internal sectioning to fence the quadrants until their next major edit, when they should be split.
- `CLAUDE.md` "Where to look" section is updated to reflect the new paths.
- All internal markdown links pointing at the moved files are rewritten.

### What does not change

- `README.md` stays at the repo root (it's the project landing page, not user docs).
- `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `LICENSE`, `LICENSES/` stay at the repo root because OSS conventions and GitHub UI both expect them there.
- The schema_version / JSON output / CLI surface — none of those are docs concerns.
- `.claude/skills/` keeps its current shape — skills are operational, not documentation.

### What gets harder

- Reviewers have to know which quadrant a new doc belongs in. The `docs/README.md` and the rules in this ADR address that, but it's a real cost on the first few PRs.
- External tutorials, blog posts, or bookmarks that link to `docs/CODING_RULES.md` will 404. Mitigated by a stub redirect (a one-line `docs/CODING_RULES.md` saying "moved to `contributors/coding-rules.md`") if external links are observed in the wild — not added preemptively.
- Splitting mixed-purpose docs is real work that adds up. Done lazily: each mixed doc gets fenced sections now, gets split when next touched.

## Alternatives considered

### Alternative 1: Good Docs Project templates

[Good Docs](https://www.thegooddocsproject.dev/) provides templates for README, CONTRIBUTING, CHANGELOG, etc. plus a style guide. Less prescriptive than Diátaxis.

**Rejected** because the templates address page-level structure but not the question of *what kind of page each doc should be*. Diátaxis answers that question; Good Docs templates assume the answer is already obvious. The two are compatible — Good Docs templates can be used inside a Diátaxis quadrant — but the structural standard has to come from Diátaxis.

### Alternative 2: Google Developer Style Guide

Tone, voice, terminology rules. Can pair with any structural standard.

**Rejected as a primary standard** for the same reason as Good Docs: it doesn't answer the structural question. Worth considering as an *additional* style standard once `docs/` has stabilized — left for a future ADR.

### Alternative 3: Status quo (ad-hoc)

Keep docs wherever they end up.

**Rejected** because the project will grow rapidly and mixed-purpose docs are already showing up at MVP 0.1. The cleanup cost compounds with every milestone.

### Alternative 4: Light Diátaxis adoption (declare the standard, defer the reorg to MVP 0.2)

Add `docs/README.md` declaring the standard, leave existing files in place, reorg later.

**Rejected** because the existing `docs/` tree is small enough that the reorg cost now is low (~2-3 hours), and it's harder to write new content in the right quadrant when the quadrants don't exist yet. Doing it now means MVP 0.2's docs land in the right places from the first commit.

## Implementation

This ADR is the first commit in the `docs/diataxis-reorg` branch. The reorg lands in the same PR as the ADR.

## Acceptance criteria

For this ADR to be considered implemented:

- [x] `docs/README.md` declares the standard
- [x] `docs/{tutorials,how-to,reference,explanation,contributors}/` directories exist
- [x] Existing user-facing docs are moved to the correct quadrant via `git mv`
- [x] Existing engineering/agent docs are moved to `docs/contributors/`
- [ ] At least one doc per quadrant has substance (not just placeholders)
- [ ] Mixed-purpose docs (`SECURITY.md`, `oss-standards.md`, `agent-antipatterns.md`) carry an editorial note flagging the split-on-next-touch
- [ ] All internal markdown links pointing at moved files are updated
- [ ] `CLAUDE.md` "Where to look" reflects the new paths
- [ ] `README.md` has a "Documentation" section linking to the four quadrants
- [ ] `reuse lint` passes (file moves can break SPDX coverage; verify)
