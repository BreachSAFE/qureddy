# Phase-gate check — full procedure

This reference expands on the "How to run a phase-gate check" section of SKILL.md. It's
the deeper procedure for the single most load-bearing thing this skill does: catching
proposed work that skips ahead of what the platform has actually authorized.

## Why this exists

A multi-phase platform build (bottom-up, each layer depending only on the one below) is
easy to violate by accident — someone gets excited about a SaaS control-plane feature, or
a key-custody backend, while the layer underneath it is still mid-build. The cost of
building out of order isn't just wasted work; it's building against an interface that
hasn't stabilized yet. The governing ADR for this kind of platform typically says so
explicitly: "commit to the order, not the timeline."

This check is advisory, not a hard gate enforced by tooling — its job is to make sure the
tradeoff is *seen and decided on purpose*, not to auto-block anything.

## Step 1 — locate the governing ADR

Look in the architecture repo's `docs/adr/` (or equivalent) for the platform-level vision
or architecture ADR — the one that lays out the full capability map and a layered/phased
build order, as opposed to a component-specific ADR (e.g. one about a single library's API
surface). Signals it's the right one:

- Title mentions the platform's umbrella name, "vision," or "architecture," not a single
  component.
- Contains a layered diagram or table (phases/tiers) with a build order.
- States explicitly what's authorized now vs. held for later.

If a top-level multi-repo orientation file exists (a README or CLAUDE.md one level above
all the component repos), it may summarize the phase table — treat that summary as a
pointer to the ADR, not a replacement for reading it; the ADR is the source of truth and
the summary can drift out of sync with it.

If more than one repo has a copy of the same ADR (e.g. because a "build starts at layer N"
component keeps a copy for local reference), diff them if you have reason to suspect drift,
and prefer whichever copy is in the repo that "owns" platform architecture ADRs.

## Step 2 — read the phase table, not just the diagram

The build-order diagram gives you the shape; the surrounding prose gives you the actual
gate. Look specifically for a section that says what's explicitly NOT authorized yet — this
is usually stronger and more specific than "later phases," e.g. "authorize building
anything above Phase N — code starts at [layer]." That sentence is the actual gate text;
quote it back to the user when flagging a violation rather than paraphrasing from the
diagram alone.

Also check for:
- Which phase is marked done/shipped (✅ or equivalent).
- Which phase is marked current/in-progress (the active build target).
- Which phases are explicitly "open questions, hold, do not decide now" — proposing to
  *discuss or write a stub ADR* for one of these is fine; proposing to *ship code or
  infrastructure* for one is the violation.

## Step 3 — map the proposed work to a phase

Ask what the proposed work actually needs to exist:

- Does it require persistent state / a datastore that doesn't exist yet in an
  already-authorized phase?
- Does it require a network-facing service (a server, an API surface) where the current
  phase is scoped to a stateless library?
- Does it require multi-tenancy, billing, RBAC, or other control-plane concerns reserved
  for the top-most phase in most such platform designs?
- Does it depend on an infra decision the ADR explicitly deferred (e.g. datastore choice,
  cache choice, auth model) as still-open?

If any of these are true and the work isn't inside the current/authorized phase, it's a
phase-gate flag.

## Step 4 — report, don't silently resolve

Present findings as:

> **Phase-gate check:** proposed work `<summary>` requires `<capability>`, which the
> platform ADR (`<path>`, dated `<date if present>`) places in `<Phase N, name>`. Current
> authorized phase is `<Phase M, name>`. This is `<in-sequence | ahead of sequence>`.

If ahead of sequence, don't recommend killing the proposal outright — options to lay out
for the user:
- Descope the proposal to only the current-phase-compatible pieces (e.g. design the API
  shape now, defer the stateful implementation).
- Write it up as a stub ADR / open question, explicitly not authorizing code yet (the
  platform ADR itself is a precedent for this pattern — "vision, not a build commitment").
  This skill may draft such a stub with the user's authorization but does not commit it.
- Get explicit authorization from whoever owns roadmap calls (per each repo's own
  governance doc, if one exists — e.g. a documented "final calls" role) to jump the queue,
  and record why.

## Worked example (pattern, not a literal transcript)

A proposal to build a hosted secrets-vault feature arrives while the active phase is still
a stateless certificate-authority library one layer below it in the stack. The vault
feature needs a persistent keystore and a stateful service — both explicitly scoped to a
later phase, and the ADR's build-sequence section says not to skip the sequence. Correct
response: flag it, quote the ADR's own "not authorized yet" language, and offer the
descope/stub-ADR/explicit-override options above rather than silently building it or
silently telling the user no.
