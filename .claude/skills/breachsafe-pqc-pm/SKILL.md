---
name: breachsafe-pqc-pm
description: Cross-repo product/program-management skill for the BreachSAFE Quantum Platform (BQP) — sequences and prioritizes PQC migration work, checks proposed work against the platform's phase-gate build order, sanity-checks ADRs/roadmaps for a real PQC migration story, and rolls up "where are we" status across repos. Use when planning, sequencing, or roadmapping work that spans more than one BQP component, when someone proposes a new ADR or milestone, or when asked what to build next / where the platform stands.
---

# breachsafe-pqc-pm

**Applies to:** platform-wide (BreachSAFE Quantum Platform / BQP), and by extension all
five components — QuCrypt, QuCert, QuCustody, QuReddy, Qurum — whenever the question
crosses a repo boundary or touches sequencing/roadmap/ADR decisions rather than code in
one repo.

## Stop and read this first: authorization gate

This skill is planning and advisory only. It may read any repo (`git log`, `git status`,
`git diff`, `gh issue list`, `gh pr list`, reading files) freely. It must **never**, on its
own initiative:

- file or comment on a GitHub issue,
- change a label,
- open, push to, or merge a PR,
- run any git operation beyond read-only inspection (no `commit`, `push`, `merge`, `tag`,
  branch creation, etc.),
- edit an ADR, roadmap, or milestones file in place.

It may **draft** issue text, PR descriptions, ADR updates, or roadmap edits and present them
to the user. It executes none of it until the user gives explicit, in-conversation
authorization for that specific action. If asked to "just file it" as part of a larger
request, treat that as the authorization for that one action — but still show what will be
filed before running the command, and don't chain it into further unauthorized actions.

## Stay in its lane

This skill does not write code, does not audit code for correctness or security, and does
not review PRs. If the actual ask is one of those, say so and point at the right skill
instead of doing it here:

- Writing/implementing a feature → `breachsafe-implement`
- Correctness/quality review of a diff → `breachsafe-quality-review`
- Security-focused audit → `breachsafe-security-audit`
- Standards/spec conformance (RFC/FIPS/NIST) → `breachsafe-conformance`
- Release mechanics (versioning, changelog, publish) → `breachsafe-release`

This skill's job is upstream of all of those: deciding *what* should happen and *in what
order*, not *how* to build or verify it.

## What this skill does

1. **Phase-gate check** — given a proposed piece of work (feature, ADR draft, milestone
   plan), check it against the platform's layered build order and flag anything that skips
   ahead of what's currently authorized. See `references/phase-gate-check.md` for the full
   procedure and how to locate the governing ADR.
2. **Sequencing and prioritization** — help order open work using each repo's own
   issue-driven conventions (comment-intended-approach-before-coding, reference the issue
   in every commit, close only after tests are green, P0/P1/P2-style triage where a repo
   uses it). Don't invent a new priority scheme — discover and follow the one already in
   use in the target repo's own CLAUDE.md / CONTRIBUTING docs.
3. **PQC-migration-story sanity check** — when reviewing a new ADR or roadmap change,
   check it doesn't silently commit to a classical-only crypto path with no migration
   story. See `references/nist-cnsa-timeline.md` for the regulatory pressure this responds
   to, and re-verify any date before it's used in a real compliance claim.
4. **Cross-repo status rollup** — when asked "where are we," report by pointing at each
   repo's own source of truth (its `CLAUDE.md`, roadmap/milestones doc, open issues) rather
   than restating numbers here. Numbers copied into this skill go stale; numbers read live
   from the repo don't.

## How to run a phase-gate check

1. Find the platform vision/architecture ADR (search each repo's `docs/adr/` for the one
   that lays out the build order/phases — commonly named along the lines of "platform
   vision" or "architecture"). Don't assume a fixed path; different repos may lead with a
   different copy or a symlink to the canonical one.
2. Read its current phase markers (what's done, what's the current/authorized phase, what's
   explicitly not-yet-authorized). Treat this ADR, not any cached memory of it, as the
   source of truth — it changes over time.
3. Map the proposed work to a phase. If it lands above the current phase (e.g. it needs a
   stateful service, a datastore, multi-tenancy, or a control plane while the platform is
   still working through a stateless/library phase), that's a flag, not an automatic
   rejection — the ADR's own language usually distinguishes "hold this decision for later"
   (fine to think about, discuss, write a stub ADR for) from "do not start building this
   yet" (should not land as shipped code/config this cycle).
4. Report the mapping and the flag (if any) to the user; do not silently downgrade or
   silently wave through the proposal. Let the user decide whether the exception is
   warranted.

Full procedure and a worked example: `references/phase-gate-check.md`.

## How to sequence/prioritize open work

- Discover the target repo's own workflow conventions before applying any priority scheme —
  look for an issue-driven workflow section in that repo's CLAUDE.md/CONTRIBUTING, and for
  any existing P0/P1/P2 or milestone labels via `gh issue list --repo <owner>/<repo> --state
  open --label ...` / `gh label list`.
- Common shape seen across BQP repos (verify per-repo, don't assume it's universal): find
  the relevant open issue first, comment the intended approach before writing code,
  reference the issue number in every commit, close only after the test suite is green —
  never by comment alone. File new issues for bugs discovered mid-work instead of
  scope-creeping the current one.
- When multiple repos have competing asks, prioritize using the phase-gate check above as
  the primary filter (lower-phase / already-authorized work generally beats higher-phase
  work that isn't authorized yet), then apply each repo's own severity/priority
  conventions within that.
- Present the resulting sequence as a recommendation with reasoning, not as an executed
  decision — sequencing calls that affect roadmap belong to the project lead unless you've
  been told otherwise for this conversation.

## How to sanity-check a PQC migration story

- Read the proposed ADR/roadmap text and ask: does this decision assume classical crypto
  only, with no stated path to PQC or hybrid? A pure classical choice isn't automatically
  wrong (e.g. a scoped interop shim), but it should be *labeled* as such, not silently
  defaulted into.
- Cross-check any date or mandate claim (e.g. "we have until 20XX") against
  `references/nist-cnsa-timeline.md` — and flag to the user that the table itself needs
  re-verification against a primary source (nist.gov, a specific NIST IR/SP, or CNSA 2.0
  guidance) before it's used in any real compliance claim to a customer or auditor. Do not
  assert specific compliance deadlines from memory beyond what's in that reference, and do
  not present the reference table itself as already-verified.
- Check whether the component in question already has a stated PQC posture (e.g. "PQC-only
  generate, broad verify" is a documented principle in at least one BQP component) and flag
  if a new proposal contradicts it without discussion.

## How to roll up cross-repo status

When asked "where are we" / "what's the state of the platform":

1. Enumerate the repos in scope (ask, or infer from the working directory / any local
   multi-repo index file if one exists — don't hardcode a repo list here, since it drifts).
2. For each repo, read its own CLAUDE.md (or equivalent onboarding doc) and its own
   roadmap/milestones doc for current status — quote or summarize what's there rather than
   re-deriving or guessing.
3. Present a rollup table (repo, product name, status, source doc) and cite the file path
   for each line so the user can verify or refresh it later.
4. Do not cache these numbers into this skill file or into any other file this skill
   writes without authorization — the whole point is that this rollup is computed fresh
   each time, from files that are the actual source of truth.

## References

- `references/phase-gate-check.md` — full phase-gate procedure, how to locate the
  governing platform ADR, and a worked example of flagging out-of-sequence work.
- `references/nist-cnsa-timeline.md` — NIST PQC standards and CNSA 2.0 timeline reference
  table (dates as researched, marked for re-verification), for grounding migration-urgency
  conversations.
