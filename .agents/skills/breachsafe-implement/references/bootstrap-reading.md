# Bootstrap reading — before you write any code

## The generalized pattern

Every BQP repo has some version of this doc set, even if the file names differ. Read them in
this order before touching code:

1. **Orientation doc** — the repo's `CLAUDE.md` (and, if present, its `AGENTS.md` mirror for
   Codex — check both; they drift from each other and from reality independently). Tells you
   current status, build/test commands, and where the other docs live.
2. **Coding-standards doc** — the authoritative engineering-standards document (naming,
   sizing, error handling, security bar, testing rules). This is the doc that wins when your
   instinct disagrees with local convention.
3. **Architecture doc** — the current module/crate layout, layering, and load-bearing
   invariants. Treat this as more current than the orientation doc's prose when the two
   disagree about file paths or structure (see "Docs go stale" below).
4. **Locked-scope / locked-schema doc**, if the feature area has one — a milestone spec, a
   skill file with locked Pydantic models, an ADR that fixes a wire format. These constrain
   what you're allowed to add/remove/rename without explicit authorization.
5. **Anti-pattern / self-audit checklist doc**, if one exists — the pre-response checklist
   you audit your own diff against before calling the work done.

If a rule in a narrower doc (a skill file, a milestone spec) conflicts with the coding-
standards doc, the coding-standards doc wins — surface the conflict, don't silently resolve
it either direction.

## Docs go stale — verify structural claims against the real tree

This is not theoretical: while writing this skill, `breachsafe-crypto-rs`'s `CLAUDE.md` and
`AGENTS.md` both described a flat `src/` layout (`src/lib.rs`, `src/kem_ffi.rs`, `src/kdf.rs`,
...). The actual repo is a Cargo workspace; the real crate lives at
`crates/qucrypt-core/src/`, reorganized into per-primitive subdirectories (`sign/`, `kem/`,
`aead/`, `kdf/`). `docs/ARCHITECTURE.md` documents the real layout and explicitly calls out
that the flat-file docs are historical. Nobody had gone back to fix `CLAUDE.md`/`AGENTS.md`.

The lesson generalizes: onboarding-doc prose about file paths rots faster than architecture
docs or the tree itself. Before relying on a specific path from `CLAUDE.md`, `AGENTS.md`, or
an old skill file, confirm it with `ls`/`find` on the actual repo, or check the architecture
doc's module-structure section if one exists. If you find a live discrepancy, say so in your
final response rather than silently working around it — the human maintaining that doc wants
to know it's drifted.

## Known doc locations per repo (verify before relying on — these move)

**`breachsafe-crypto-rs` (QuCrypt):**

| Doc | Path (from repo root) |
|---|---|
| Orientation | `CLAUDE.md`, `AGENTS.md` |
| Coding standards / invariants | `CLAUDE.md` (Critical Invariants, Thin Wrapper Rule, Zeroize Rules sections) |
| Architecture / current module layout | `docs/ARCHITECTURE.md` — source of truth for file layout, supersedes onboarding-doc prose |
| API hazard reference | `docs/reference/openssl/*.md` (per-primitive), `docs/reference/zeroize.md` |
| Workflow / priorities | issue-driven — `gh issue list --repo <owner>/breachsafe-crypto-rs --state open` |

**`qureddy` (QuReddy):**

| Doc | Path (from repo root) |
|---|---|
| Orientation | `CLAUDE.md` |
| Coding standards | `docs/contributors/coding-rules.md` |
| Agent operating discipline / pre-response audit | `docs/contributors/agent-antipatterns.md` |
| Good-vs-bad code patterns | `docs/contributors/examples.md` |
| CLI-specific rules | `docs/contributors/cli-design-rules.md` |
| Locked scope for a milestone | the relevant `.claude/skills/<milestone>-implement/SKILL.md` if one exists, or `docs/reference/milestones.md` |
| TLS-scanner fixture/target catalog | `tests/fixtures/openssl/TARGETS.md` (only when touching the TLS scanner) |

**Other BQP repos** (`breachsafe-pki-rs`, `breachsafe-custody`, `quorum`) — apply the same
pattern: find the repo's own `CLAUDE.md`/orientation doc first, follow its pointers. Don't
assume these repos mirror crypto-rs's or qureddy's doc layout exactly; confirm per repo.

## A caution on borrowed skill files

Skills get copy-pasted between repos without adaptation more often than you'd expect — e.g.
a skill run from one repo that still literally describes auditing a *different* repo by name.
If a skill file's self-description doesn't match the repo you're actually in, treat it as
untrustworthy for that repo and fall back to the repo's own `CLAUDE.md`/architecture doc
instead of the skill's stale claims.
