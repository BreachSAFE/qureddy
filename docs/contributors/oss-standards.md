# OSS Standards for BreachSAFE QuReddy

This project commits to the following standards. Pull requests that violate them will be revised before merge.

## Contents

- [Agent working standard](#agent-working-standard)
- [Repository hygiene](#repository-hygiene)
- [Documentation hygiene](#documentation-hygiene)
- [Code hygiene](#code-hygiene)
- [Community hygiene](#community-hygiene)
- [Release hygiene](#release-hygiene)
- [Things we do not do](#things-we-do-not-do)

## Agent working standard

Agents working on this repo follow the contract in `docs/contributors/agent-antipatterns.md`. The summary commitment:

- Read relevant code, tests, and config before editing.
- Keep changes scoped to the user's request.
- Preserve unrelated user work and avoid broad formatting churn.
- Follow existing project patterns unless there is a clear reason to change them.
- Verify the change. The full definition of "narrowest meaningful check" lives in `docs/contributors/agent-antipatterns.md` under "Verify behavior".
- Final responses state what changed, what was verified, and any remaining risk.

---

## Repository hygiene

- Every source file has an SPDX-License-Identifier header.
- Every release is tagged with semver and has a changelog entry.
- Every commit follows Conventional Commits format.
- The repo never contains commented-out code, secrets, or local-only config. Generated artifacts are checked in only if they are reproducible build outputs (lockfiles, recorded test fixtures); never agent scratch files or local environment dumps.

---

## Documentation hygiene

- The README is readable in 60 seconds.
- README quick start includes a working install path and first useful command.
- Code blocks in docs are tested or manually verified before commit.
- ARCHITECTURE.md explains design decisions, not just what the code does.
- CHANGELOG.md follows keep-a-changelog format.
- User docs, contributor docs, and release docs stay separated by audience.

---

## Code hygiene

- All code passes ruff check, mypy strict, and pytest.
- All public functions have docstrings.
- All modules have a single clear purpose.
- All subprocess calls are list-form, never shell=True.
- External calls have explicit timeouts.
- Inputs crossing trust boundaries are validated and represented with typed structures.

---

## Community hygiene

- Issues get a response within 7 days.
- PRs get a response within 7 days.
- Contributors are credited in CHANGELOG entries.
- The maintainer responds to security reports within 5 business days.

---

## Release hygiene

- CI must pass before merge to main.
- main is always releasable.
- Release signing with Sigstore is a planned hardening step, not a claim about
  the current candidate.
- Each release has a release note with what-changed-and-why.
- The repository-owned local release gate builds and verifies the candidate
  artifacts. Hosted CI mirrors that gate on supported platforms before merge.
- Publication uses the exact verified candidate artifacts and requires explicit
  release authorization.

---

## Things we do not do

- We don't merge to main without CI passing.
- We don't ship features without tests.
- We don't ship without a CHANGELOG entry.
- We don't accept PRs that violate the anti-pattern catalog without explicit reasoning.
- We don't add abstractions, dependencies, or public API changes speculatively.
- We don't claim verification that was not actually run.
