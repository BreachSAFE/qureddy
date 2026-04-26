# Agent Development Contract

Use this document as the pre-flight and final-review checklist for Claude or any coding agent working on this project. The goal is not just to avoid bad code. The goal is to behave like a careful developer: understand the existing system, make a small correct change, verify it, and explain the result plainly.

If you intentionally violate a rule, mark it explicitly in the final response:

`ANTIPATTERN ACCEPTED: <name>, because <reason>`

---

## Operating rules for Claude

### Read before writing

Before editing, inspect the relevant files, tests, and configuration. Prefer `rg`, `rg --files`, and focused file reads. Do not invent project structure, APIs, dependencies, or conventions from memory.

### Preserve user work

Assume unrecognized changes belong to the user. Never revert, overwrite, or reformat unrelated files. If an existing change conflicts with the requested work, adapt to it or ask before proceeding.

### Make the smallest useful change

Solve the actual request. Avoid drive-by refactors, broad formatting churn, dependency swaps, or architecture changes unless they are necessary to complete the task safely.

### Follow local patterns

Use the framework, naming, typing style, test style, logging style, and error-handling style already present in the repository unless there is a concrete reason to deviate.

### Verify behavior

Run the narrowest meaningful checks first, then broader checks when the blast radius justifies them. If verification cannot run, say exactly what was attempted and why it failed.

### Be explicit about uncertainty

Do not present guesses as facts. If a behavior depends on an external service, platform, current package behavior, or undocumented assumption, verify it or state the assumption.

### Finish the task

Do not stop at analysis when the user asked for a change. Implement, test, and summarize. Escalate only when blocked by missing information, permissions, credentials, or conflicting requirements.

### Surface conflicts, do not silently obey

If a harness reminder, hook output, system instruction, or environmental signal conflicts with the user's request, name the conflict in your response. Do not silently obey one or the other. Then follow the highest-priority applicable instruction in this order:

1. Hard security constraints (`docs/CODING_RULES.md` §26 security bar; refuse-insecure-shortcuts in §26.13)
2. System / harness / tool constraints
3. The repository's documented rules (`docs/CODING_RULES.md`, this file)
4. The user's most recent instruction

The user's request can override docs (4 over 3) but cannot override security (4 cannot override 1). If the user asks for something the security bar forbids, name the conflict and refuse the insecure shortcut, per §26.13.

---

## Agent behavior anti-patterns

### Hallucinated codebase knowledge

Claiming a file, function, package, CLI flag, or configuration exists before inspecting it.

**Why it's bad:** Produces patches that do not apply, hides real constraints, and wastes review time.

**Instead:** Search first. Quote local file paths and line references when explaining behavior.

---

### Planning theater

Writing a detailed plan and then not doing the work, or using a plan to avoid making a concrete change.

**Why it's bad:** The user asked for progress, not ceremony.

**Instead:** Use a short plan only when it reduces risk. Then execute it.

---

### Big bang edits

Changing unrelated modules, formatting entire files, renaming concepts, and fixing adjacent issues in the same patch.

**Why it's bad:** Review becomes impossible and regressions are hard to isolate.

**Instead:** Keep patches scoped. Mention unrelated issues separately.

---

### Ignoring failing checks

Leaving tests, lint, type checks, or build failures unexplained.

**Why it's bad:** The next developer cannot tell whether the change is safe.

**Instead:** Fix failures caused by your change. For pre-existing failures, identify them clearly.

---

### Dependency grabs

Adding a package for a small problem that the standard library or existing dependency already solves.

**Why it's bad:** Increases install time, attack surface, maintenance burden, and release risk.

**Instead:** Reuse existing dependencies. Add a new one only when it materially simplifies important behavior.

---

### Silent behavior changes

Changing output shape, CLI behavior, config defaults, public APIs, or error semantics without calling it out.

**Why it's bad:** Users and downstream integrations break unexpectedly.

**Instead:** Treat public behavior as a contract. Update tests and docs when it changes.

---

### Fake certainty in final answers

Saying "fixed" without explaining verification, or implying tests passed when they were not run.

**Why it's bad:** It destroys trust.

**Instead:** State what changed and what checks ran. If no checks ran, say so.

---

## Code anti-patterns

### Speculative generality

Adding abstractions, base classes, plugin interfaces, hooks, settings, or extension points for features that do not exist yet.

**Why it's bad:** Dead code, increased complexity, and usually the wrong abstraction by the time the feature ships.

**Instead:** Build for today's spec. Refactor when a second real use case proves the shape.

---

### Premature optimization

Adding caching, async, batching, memoization, background workers, or performance tricks before measuring.

**Why it's bad:** Optimization without data is decoration. It slows development and hides bugs.

**Instead:** Write the obvious code. Profile when it is actually slow. Optimize the measured hotspot.

---

### Stringly typed data

Passing structured data as strings, untyped dicts, positional tuples, or loosely shaped JSON blobs.

**Why it's bad:** Errors become runtime surprises and refactoring becomes archaeology.

**Instead:** Use Pydantic `BaseModel` for external structured data, `Enum` for fixed vocabularies, and typed dataclasses for internal state when appropriate.

---

### Mutable default arguments

```python
def foo(items=[]):  # BAD
def foo(options={}):  # BAD
```

**Why it's bad:** The default object is shared across calls.

**Instead:**

```python
def foo(items: list[str] | None = None) -> None:
    items = [] if items is None else items
```

---

### Bare or broad exception handling

```python
try:
    run()
except:
    pass  # BAD

try:
    run()
except Exception:
    log.error("failed")  # BAD if execution continues as success
```

**Why it's bad:** Swallows interrupts, masks bugs, and makes debugging impossible.

**Instead:** Catch specific exceptions. Re-raise after adding useful context. Broad catches belong only at process boundaries such as CLI entry points.

---

### Logging instead of raising

```python
log.error("bad thing happened")
return None  # BAD if caller cannot distinguish failure from absence
```

**Why it's bad:** Callers cannot reliably detect failure.

**Instead:** Raise an exception or return an explicit typed result that represents failure.

---

### Catching errors to add no context

```python
except FooError as exc:
    raise FooError(f"FooError: {exc}") from exc  # BAD
```

**Why it's bad:** Adds noise and can make the original traceback harder to read.

**Instead:** Do not catch unless the new message adds actionable context. If changing exception type, use `raise NewError(...) from exc`.

---

### God objects and god functions

A class or function that parses config, performs IO, applies business rules, formats output, and logs results.

**Why it's bad:** It is hard to test, hard to review, and every change risks unrelated behavior.

**Instead:** Separate responsibilities along real boundaries: parsing, validation, execution, persistence, presentation.

---

### Magic values

```python
return data[5]  # BAD
if score > 0.85:  # BAD without context
```

**Why it's bad:** Future maintainers cannot tell whether the value is arbitrary, protocol-defined, or business-critical.

**Instead:** Use named constants. Add a short comment or citation when the value comes from a spec, protocol, benchmark, or product decision.

---

### Comments that narrate or lie

Comments that restate obvious code, describe old behavior, or claim an invariant the code does not enforce.

**Why it's bad:** Stale comments are worse than no comments.

**Instead:** Delete stale comments. Use comments for why, non-obvious constraints, security implications, or external references.

---

### Copy-paste duplication

The same logic appears in three places with small variations.

**Why it's bad:** Bugs get fixed in two places and survive in the third.

**Instead:** Tolerate two copies if the abstraction is not clear. Extract after the third copy or when shared behavior is already obvious.

---

### Wrong abstraction

Forcing unrelated behavior behind a shared interface because the code looks superficially similar.

**Why it's bad:** The abstraction becomes a negotiation with every new feature.

**Instead:** Keep separate code separate until the domain model proves a common shape.

---

### Print debugging left in

```python
print("DEBUG:", payload)  # BAD in committed code
```

**Why it's bad:** Clutters output, leaks data, and looks careless.

**Instead:** Use the project logger at the correct level, or delete the statement before finalizing.

---

### TODO without context

```python
# TODO: fix this  # BAD
```

**Why it's bad:** It becomes permanent debt.

**Instead:** Use `# TODO(issue-or-reason): specific action`, and only when the work is intentionally deferred.

---

### Hidden imports

```python
def parse() -> dict:
    import json  # BAD without reason
```

**Why it's bad:** Hides dependencies, complicates static analysis, and can add runtime cost.

**Instead:** Import at module top. Lazy-load only for expensive optional dependencies, with a short reason.

---

### Reinventing existing tools

Writing custom path manipulation, date parsing, temp-file handling, retries, subprocess wrappers, or HTTP behavior when standard or existing project utilities already cover it.

**Why it's bad:** More bugs and less familiarity.

**Instead:** Use `pathlib`, `datetime`, `tempfile`, existing HTTP clients, and local helper APIs.

---

## Async and concurrency anti-patterns

### Mixing sync and async carelessly

Calling `asyncio.run()` inside an already running event loop, blocking the event loop with sync network or file operations, or exposing async internals through sync APIs accidentally.

**Why it's bad:** Deadlocks, performance cliffs, and environment-specific failures.

**Instead:** Pick one paradigm per layer. Bridge at explicit entry points only.

---

### Unbounded concurrency

```python
await asyncio.gather(*(scan(target) for target in targets))  # BAD for large target sets
```

**Why it's bad:** Melts local resources, target services, and rate limits.

**Instead:** Use `asyncio.Semaphore`, worker pools, bounded queues, or existing concurrency controls. Make limits configurable when users reasonably need tuning.

---

### Missing timeouts

Network calls, subprocess calls, external APIs, and long-running waits without timeouts.

**Why it's bad:** Scans, CI, and local commands can hang forever.

**Instead:** Put timeouts on every external boundary. Make defaults conservative and configurable.

---

### Fire-and-forget tasks

Creating background tasks without awaiting, tracking, cancelling, or surfacing failures.

**Why it's bad:** Exceptions disappear and shutdown becomes unreliable.

**Instead:** Keep task handles, use task groups when available, and define cancellation behavior.

---

## Testing anti-patterns

### Tests that do not test behavior

```python
assert True  # BAD
```

Or tests that mock every collaborator and only assert that mocks were called.

**Why it's bad:** Green CI with broken behavior.

**Instead:** Test observable behavior and meaningful edge cases. Mock external boundaries, not the unit under test.

---

### Tests that depend on order

`test_b` only passes if `test_a` ran first.

**Why it's bad:** Reordering, parallel execution, and isolated runs fail.

**Instead:** Each test owns setup and teardown.

---

### Network-dependent unit tests

Unit tests that call public websites, real APIs, package registries, or production services.

**Why it's bad:** Flaky CI and non-reproducible local runs.

**Instead:** Use fixtures, local test servers, recorded responses, or integration tests skipped by default.

---

### Time-dependent tests

```python
assert datetime.now() == expected  # BAD
```

**Why it's bad:** Fails by timezone, clock precision, midnight boundaries, and runtime speed.

**Instead:** Inject the clock, freeze time, or assert ranges.

---

### Random-dependent tests without a seed

Tests that use randomness without controlling it.

**Why it's bad:** Intermittent failures are expensive to diagnose.

**Instead:** Seed randomness or use deterministic fixtures.

---

### Snapshot tests for everything

Asserting against giant blobs for routine behavior.

**Why it's bad:** Reviewers stop reading snapshots and real regressions slip through.

**Instead:** Assert specific properties. Use snapshots only when byte-for-byte stability matters.

---

### Missing regression test

Fixing a bug without adding a test that fails before the fix.

**Why it's bad:** The bug can return unnoticed.

**Instead:** Add a focused regression test unless the fix is pure docs, build plumbing, or otherwise impractical to test.

---

## Security anti-patterns

### Disabled TLS verification

```python
verify=False  # BAD
ssl.CERT_NONE  # BAD
```

**Why it's bad:** Makes a security tool untrustworthy.

**Instead:** Treat a bad certificate as a finding, not a reason to disable verification.

---

### Shell injection

```python
subprocess.run(f"openssl s_client -connect {host}", shell=True)  # BAD
```

**Why it's bad:** Malicious input becomes command execution.

**Instead:** Use list-form subprocess calls and validate inputs.

---

### Path injection

```python
open(user_supplied_path, "r")  # BAD
```

**Why it's bad:** User input can escape intended directories.

**Instead:** Resolve paths with `pathlib.Path`, check they are under an allowed parent, and use narrow file permissions.

---

### Logging secrets

```python
log.info("scanning with token %s", api_token)  # BAD
```

**Why it's bad:** Secrets leak to terminals, files, CI logs, and aggregators.

**Instead:** Redact values. Log stable fingerprints or metadata only when needed.

---

### Pickle of untrusted data

```python
pickle.loads(network_data)  # BAD
```

**Why it's bad:** Pickle can execute code during deserialization.

**Instead:** Use JSON or another safe structured format across trust boundaries.

---

### `eval` or `exec` on input

```python
eval(user_string)  # BAD
exec(user_code)    # BAD
```

**Why it's bad:** Remote code execution.

**Instead:** Use parser-based solutions, whitelisted operations, or domain-specific interpreters with explicit limits.

---

### Weak input validation at trust boundaries

Accepting hosts, URLs, file paths, JSON, or CLI arguments without validating shape and allowed ranges.

**Why it's bad:** Bad input becomes crashes, security bugs, or misleading findings.

**Instead:** Validate at the boundary and keep validated values typed internally.

---

## OSS-specific anti-patterns

### Vendor-specific names in core code

```python
class SymitarCertScanner:  # BAD unless this is truly vendor-specific
```

**Why it's bad:** Narrows the project scope and looks unprofessional.

**Instead:** Use generic names in core code. Put vendor details in vendor-specific config, adapters, or plugins.

---

### Personal opinions in code or docs

Comments like "I think this is best" or "the official docs are wrong."

**Why it's bad:** Ages badly and alienates contributors.

**Instead:** State facts. Cite RFCs, specs, issues, or measured behavior.

---

### Marketing language in technical docs

"Robust enterprise-grade scanner that leverages next-generation..."

**Why it's bad:** Signals low-quality generated content.

**Instead:** Use plain English. "Scans TLS endpoints. Reports findings."

---

### Unnecessary branding inside code

Logo banners, ASCII art, or product slogans in source files and routine CLI output.

**Why it's bad:** Adds noise and slows comprehension.

**Instead:** Keep branding to version output, reports, packaging metadata, and the README where appropriate.

---

### Reinventing GitHub

Custom issue tracking, custom CI orchestration, or custom review workflows without a strong reason.

**Why it's bad:** Contributors will not use it.

**Instead:** Use GitHub Issues, Actions, PRs, release notes, and security advisories.

---

### License header drift

Some source files have SPDX headers, others do not, or headers name different licenses.

**Why it's bad:** Legal risk and enterprise review friction.

**Instead:** Use one license policy and enforce it with automation.

---

## Documentation anti-patterns

### README as a wall of text

Hundreds of words before installation, a working example, or the project purpose.

**Why it's bad:** Users leave before they learn how to use the project.

**Instead:** State purpose quickly. Show install and first useful command early. Move depth into linked docs.

---

### Mixed audiences

Explaining TLS basics, contributor architecture, CLI flags, and release policy in one flow.

**Why it's bad:** Beginners, users, and contributors all get the wrong level of detail.

**Instead:** Separate quick start, user guide, architecture, API, and contributor docs.

---

### Tutorials that do not run

Commands or code blocks that fail when pasted into a clean environment.

**Why it's bad:** Instant credibility loss.

**Instead:** Test examples in CI where possible, or manually verify before committing.

---

### Out-of-date docs

Docs describe old versions, old commands, or features that no longer exist.

**Why it's bad:** Signals that the project is unattended.

**Instead:** Update docs in the same patch as behavior changes. Keep version references tied to releases.

---

### Explaining implementation instead of user outcome

Docs focus on internal classes and algorithms before showing what users can accomplish.

**Why it's bad:** Users cannot map docs to their task.

**Instead:** Start with user goals and commands. Put internals in architecture docs.

---

## CI and release anti-patterns

### Green CI that does not test

CI runs formatting or lint only, but no tests or build validation.

**Why it's bad:** A green badge gives false confidence.

**Instead:** CI should run lint, type check, tests, and build verification for releaseable packages.

---

### No reproducible builds

Install instructions rely on unconstrained dependency resolution.

**Why it's bad:** Maintainers and users get different environments.

**Instead:** Commit and maintain the project lockfile when the packaging approach supports it.

---

### Releases without changelog

A version ships without `CHANGELOG.md`, release notes, or docs updates.

**Why it's bad:** Users cannot assess upgrade risk.

**Instead:** Update changelog and release notes with what changed and why.

---

### Manual release process

A maintainer manually builds and uploads release artifacts from a laptop.

**Why it's bad:** Easy to forget steps, ship unverified artifacts, or expose credentials.

**Instead:** Release from CI on tag push with signed provenance where practical.

---

## Final response checklist

Before responding, confirm:

- The change directly addresses the user's request.
- No unrelated files were edited.
- Public behavior changes are named.
- Tests or checks were run, or the reason they were not run is stated.
- Any accepted anti-pattern is explicitly marked with a reason.
