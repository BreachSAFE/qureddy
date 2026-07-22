# PR diff audit checklist (Mode 2)

Walk the diff line by line against the target repo's own house style / coding-rules
document (every BQP repo has one, under a name like `docs/contributors/coding-rules.md`
or a `CLAUDE.md` conventions section — find it first, don't assume section numbers or
thresholds from a different repo apply here). The point of this mode is to stop skimming:
a green test run is necessary but not sufficient. Confirm each category explicitly.

## Inputs

- The diff being audited (working tree, staged changes, or a PR branch)
- The target ref to diff against (default: the repo's main/trunk branch)
- The repo's coding-rules / style doc, read fresh — don't rely on a cached memory of a
  different repo's thresholds

## Categories to walk

For each changed source file, check:

### Size
Count function length, file length, class length against whatever limits the repo's own
style doc sets (many BQP repos use something in the neighborhood of "warn near 30-50 line
functions, block past it; warn near 300-400 line files, block past it" — but confirm the
actual numbers in-repo rather than assuming). Flag anything over the repo's own limit.

### Naming
Flag generic dumping-ground filenames (`utils.py`, `helpers.rs`, `common.py`) and any
name that violates the repo's documented naming conventions.

### Types / signatures
Confirm type hints / type annotations are present on public functions per the repo's
convention. Flag any type-suppression comment (`# type: ignore`, `#[allow(...)]`) that
lacks both a specific code and a reason. Flag schema-breaking changes to frozen /
strict data models (e.g. a Pydantic model with `frozen=True, extra="forbid"`, or a Rust
struct whose wire layout other code depends on) — adding a field to a strict schema is a
breaking change even if it "looks additive."

### Error handling, subprocess discipline, logging discipline, dead code
Shared with Mode 5 — see `references/generic-code-hygiene.md` for the checks and grep
commands. This mode's posture: read-only, report findings, don't fix (per the
authorization gate above) — the opposite posture from Mode 5's fix-your-own-work rule,
same underlying checklist. Also specific to this mode: flag bare/catch-all exception
handling and any error path that logs and silently continues where the caller expected
a hard failure signal — a slightly broader error-handling check than the panic-specific
one in the shared file.

### General security hygiene (not crypto correctness)
Flag `verify=False` / disabled TLS verification, `eval`/`exec` on untrusted input,
insecure deserialization (e.g. `pickle.loads` on untrusted data), unvalidated
user-supplied filesystem paths, and use of a non-cryptographic RNG where the repo's own
convention calls for a secure one. This is the general-hygiene layer — anything that
requires judgment about whether a *cryptographic primitive itself* is used correctly
(nonce reuse, wrong KDF label, hedged-signature assumptions, memory zeroization of key
material, timing side channels) is `breachsafe-security-audit`'s job, not this one. If
you're not sure which side a finding is on, ask: "would fixing this differently change
whether the crypto is correct, or does it only affect whether the code is well-behaved
software?" The former is `breachsafe-security-audit`.

## Use-case / feature coverage (if the repo defines one)

Some BQP repos define explicit use cases or acceptance scenarios (check for something
like a "use cases" section in an implementation skill or spec doc). If the diff touches
functionality tied to a defined use case, confirm at least one test exercises it. Don't
invent use-case IDs that aren't already defined in the repo.

## Changelog

If the diff changes user-visible behavior (new command, new flag, new exit code, new
output field), confirm the repo's changelog has an entry for it, if the repo keeps one.

## Explicit rule-violation markers

Some repos have a convention for marking an intentional, justified rule violation in the
PR/commit description (something like `ANTIPATTERN ACCEPTED: <rule>, because <reason>`).
If the repo has this convention, verify every intentional violation in the diff carries
one, and that unexplained violations don't slip through under its cover.

## Output format

```
## PR Audit Result

**Quality gates:** (delegate to rust-quality-gates.md / python-quality-gates.md — embed results)

**Diff walk:**
- Files changed: [list]
- Largest function / file: N lines in <file>
- Size: PASS / FAIL — details
- Naming: PASS / FAIL — details
- Types / schema stability: PASS / FAIL — details
- Error handling: PASS / FAIL — details
- Subprocess discipline: PASS / FAIL — details
- Logging discipline: PASS / FAIL — details
- Comments / dead code: PASS / FAIL — details
- General security hygiene: PASS / FAIL — details

**Use-case / feature coverage (if applicable):** covered / NOT COVERED — list

**Changelog:** present / NOT REQUIRED / MISSING

**Rule-violation markers (if repo has the convention):** list, or NONE

**Overall:** READY TO MERGE / NOT READY — numbered list of blocking findings
```

## Hard rules

- Don't say "PASS" without having actually walked the category. "Looks fine" is not an
  audit.
- Don't approve a diff with an unresolved general-security-hygiene finding without an
  explicit, repo-documented exception process having been followed.
- This mode is read-only / audit-only by default (see the top-level skill's
  authorization gate) — report findings, don't fix them, unless the user has explicitly
  authorized fixes as part of this run.
