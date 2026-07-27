# QuReddy Documentation

This directory follows **[Diátaxis](https://diataxis.fr)** — every documentation page belongs to exactly one of four quadrants. Mixing types in the same page is the primary doc smell Diátaxis is designed to prevent, so each page below has one job.

## Contents

- [The four quadrants](#the-four-quadrants)
- [QuReddy documentation](#qureddy-documentation)
- [Contributor documentation](#contributor-documentation)
- [Editorial rules](#editorial-rules)
- [Add a page](#add-a-page)
- [Why Diátaxis](#why-diátaxis)

## The four quadrants

|  | Theoretical (concept) | Practical (action) |
|---|---|---|
| **Studying** (learning) | [Explanation](explanation/) | [Tutorials](tutorials/) |
| **Working** (doing) | — | [How-to guides](how-to/) and [Reference](reference/) |

The split is more useful than it looks. Each quadrant answers a different reader question:

- **Tutorials** — *"I'm new. Walk me through something so I learn."* Hand-holding, guaranteed to work, no choices to make. The reader is studying.
- **How-to guides** — *"I have a goal. Show me the steps."* Task-oriented, assumes basic familiarity. The reader is working.
- **Reference** — *"I need to look something up."* Information-oriented. Comprehensive, dry, accurate. The reader is working.
- **Explanation** — *"I want to understand why."* Discusses, gives context, considers alternatives. The reader is studying.

A page that does two of these jobs is doing neither well. When in doubt, split it.

## QuReddy documentation

### [Tutorials](tutorials/)
Learning-oriented walkthroughs for someone new to the tool.

- [Your first PQ readiness scan](tutorials/your-first-scan.md)

### [How-to guides](how-to/)
Task-oriented recipes for someone who already knows the basics.

- [Install and troubleshoot QuReddy](how-to/install.md)
- [Scan an IP target with a custom SNI](how-to/scan-ip-with-sni.md)
- [Scan an SSH or SFTP endpoint](how-to/scan-ssh.md)
- [Capture machine-readable output for CI](how-to/json-output-for-ci.md)
- [Generate a CBOM](how-to/generate-a-cbom.md)

### [Reference](reference/)
Look-it-up information. Comprehensive, accurate, dry.

- [CLI options](reference/cli.md) — every flag, every default, every value
- [Exit codes](reference/exit-codes.md) — 0, 2, 3, 4, 70 and what triggers each
- [JSON output schema](reference/json-schema.md) — the locked top-level keys, every field type
- [CycloneDX CBOM output](reference/cbom.md) — emitted 1.7 components, references, metadata, and limits
- [Failure categories](reference/failure-categories.md) — the `FailureCategory` enum, what each value means, retry eligibility
- [Project milestones](reference/milestones.md) — what's shipped, what's planned
- [Editions](reference/editions.md) — capability matrix: OSS vs BreachSAFE QuReddy Enterprise (planned, P2)

### [Explanation](explanation/)
Conceptual discussion. Why we made the choices we did.

- [Architecture](explanation/architecture.md) — module map, scan flow, output stream contract, failure-category routing
- [Why hybrid post-quantum?](explanation/why-hybrid-pq.md) — the X25519MLKEM768 design call
- [Harvest now, decrypt later (HNDL)](explanation/hndl.md) — the threat model that drives the timeline
- [Threat model and scope](explanation/threat-model.md) — what QuReddy assumes, what it doesn't try to defend against
- [Evidence honesty](explanation/evidence-honesty.md) — observation, local capability, interpretation, and unknown states
- [Why QuReddy is open-core](explanation/oss-vs-enterprise.md) — what stays in OSS vs Enterprise (P2), and why

## Contributor documentation

The rules and conventions for working *on* QuReddy (not *with* it) live separately from user-facing docs:

- [`contributors/`](contributors/) — engineering rules, anti-patterns, examples, OSS standards
- [`contributors/coding-rules.md`](contributors/coding-rules.md) — Python authoring standards (size, types, security, structlog, exceptions). Source of truth for *how the code is written*.
- [`contributors/cli-design-rules.md`](contributors/cli-design-rules.md) — CLI conventions (flags, exit codes, help, stdout/stderr contract, NO_COLOR). Source of truth for *how the CLI behaves*.
- [`contributors/review-process.md`](contributors/review-process.md) — how a fix lands: reviewer / validator / arbiter pipeline + label tiers
- [`contributors/adr/`](contributors/adr/) — accepted, proposed, implemented, and superseded architecture decisions
- [`contributors/agents/`](contributors/agents/) — agent role specifications and bootstrap prompts

These follow Diátaxis internally too — `coding-rules.md` is reference, `examples.md` is how-to, etc. — but they sit under `contributors/` because they're not for end users of the `qureddy` CLI.

## Editorial rules

These keep Diátaxis from drifting:

1. **One quadrant per page.** If a page is doing two jobs, split it before merging the next change.
2. **Tutorials never reference; reference never explains.** A tutorial that says "see Reference for the full option list" is fine — that's a pointer, not a content mix. A tutorial that *includes* the full option list is not.
3. **How-to guides assume familiarity.** They don't repeat introductory material — they link to it.
4. **Reference is exhaustive but never opinionated.** No "we recommend" — that goes in How-to.
5. **Explanation has no commands.** Worked examples belong in Tutorials or How-to.
6. **Front-load the answer.** Every page starts with what it covers in 1–2 sentences. The reader should know in five seconds whether they're in the right place.
7. **No marketing voice.** This is technical documentation. "QuReddy makes PQ easy!" — no.

## Add a page

When you add a doc, ask:

1. Which of the four reader questions does it answer?
2. Could it answer two? If yes, split.
3. Is the answer "rules for contributors"? Then it's `contributors/`, not user docs.

Then create the file in the right directory and link it from this README.

## Why Diátaxis

Documentation grows organically and ends up as a mix of partial tutorials, half-references, and forum-thread-quality explanations stuck in the same files. Diátaxis is a structural fix — once a doc has a quadrant, the rules for what it cannot do are obvious, and reviewers can apply them without arguing about taste.

Adopters include Django, Cloudflare, Gatsby, Pulumi, the Rust Book ecosystem, GitLab, and Open edX. It's free, requires no tooling, and is documented at https://diataxis.fr.

The choice is recorded in [ADR 0002](contributors/adr/0002-diataxis-documentation-standard.md).
