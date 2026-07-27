# QuReddy Documentation

This directory follows **[Diátaxis](https://diataxis.fr)**. Each documentation page belongs to one of four quadrants, and each page has one job.

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
- **Reference** — *"I need to look something up."* Information-oriented, complete, dry, and accurate. The reader is working.
- **Explanation** — *"I want to understand why."* Discusses, gives context, considers alternatives. The reader is studying.

A page that does two of these jobs is doing neither well. When in doubt, split it.

## QuReddy documentation

### [Tutorials](tutorials/)
Learning-oriented walkthroughs for someone new to the tool.

- [Your first PQ readiness scan](tutorials/your-first-scan.md)

### [How-to guides](how-to/)
Task-oriented recipes for someone who already knows the basics.

- [Run with Docker and GHCR](how-to/docker.md)
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

### [Explanation](explanation/)
Conceptual discussion. Why we made the choices we did.

- [Architecture](explanation/architecture.md) — module map, scan flow, output stream contract, failure-category routing
- [Why hybrid post-quantum?](explanation/why-hybrid-pq.md) — the X25519MLKEM768 design call
- [Harvest now, decrypt later (HNDL)](explanation/hndl.md) — the threat model that drives the timeline
- [Threat model and scope](explanation/threat-model.md) — what QuReddy assumes, what it doesn't try to defend against

## Contributor documentation

The rules and conventions for working *on* QuReddy (not *with* it) live separately from user-facing docs:

- [`contributors/`](contributors/) — engineering rules, anti-patterns, examples, OSS standards
- [`contributors/coding-rules.md`](contributors/coding-rules.md) — Python authoring standards (size, types, security, structlog, exceptions). Source of truth for *how the code is written*.
- [`contributors/cli-design-rules.md`](contributors/cli-design-rules.md) — CLI conventions (flags, exit codes, help, stdout/stderr contract, NO_COLOR). Source of truth for *how the CLI behaves*.
- [`contributors/review-process.md`](contributors/review-process.md) — how a fix lands: reviewer / validator / arbiter pipeline + label tiers

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

Documentation can accumulate partial tutorials, incomplete references, and mixed-purpose explanations. Diátaxis assigns each page a quadrant, which gives reviewers a concrete scope to check.

Projects using Diátaxis include Django, Cloudflare, Gatsby, Pulumi, the Rust Book, GitLab, and Open edX. The method is documented at https://diataxis.fr.

The contributor documentation standard is maintained as an internal decision record.
