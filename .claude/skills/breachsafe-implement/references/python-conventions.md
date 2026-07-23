# Python conventions — locked-model, quality-gated CLI discipline

Grounded in `qureddy` (QuReddy) and the adjacent `quorum` (Qurum) tooling. Re-verify specifics
(exact section numbers, exact gate thresholds) against the target repo's own coding-standards
doc — treat what's below as the shape of the discipline, not a substitute for reading that doc.

## No placeholder scaffolding

Every file created must be exercised by the running command, by a test, or by tooling those
require. Do not create empty modules, unused abstractions, speculative plugin systems, fake
registries, TODO-only files, placeholder tests, or unused extension points. If a file you're
about to create can't participate in the working command path or the test suite, don't create
it — explain why in your response instead.

This is the single most common way agent-written Python in this codebase family goes wrong:
building the "obviously needed later" abstraction before there's a second real call site for
it. Add the second helper when you have the second use case, not the first.

## Locked model discipline

When a feature area has a locked Pydantic model spec (in a milestone-implement skill file, an
ADR, or a schema doc), treat it as locked:

- You may add fields only if the spec explicitly authorizes it for this task.
- Never remove a field or change its type without an explicit, discussed schema decision —
  frozen models with `extra="forbid"` mean consumers depending on the current shape will
  break silently otherwise.
- Fixed vocabularies are `Enum`, not raw strings — this catches typos at construction time
  instead of at "why isn't my rule firing" time.
- Immutable collections are `tuple[...]`, not `list[...]`.
- Datetimes are timezone-aware UTC.
- A model that's built once at the end of an operation (e.g. scan metadata capturing
  start/end time) should be constructed once, fully formed — don't build it early and mutate
  it, and don't mutate any nested model after the top-level result object is built.

If a locked spec deliberately includes fields not yet used by the current milestone (schema
stability ahead of a later milestone that will use them), that's a documented, intentional
exception — state it as `ANTIPATTERN ACCEPTED: speculative generality, because <reason tied to
the actual spec>` in your final response rather than silently complying or silently refusing.

## Subprocess-boundary discipline

When the tool's real behavior comes from an external process (OpenSSL, or any other
subprocess-driven dependency), confine every call to that process to exactly one dedicated
module — not scattered across the codebase. Within that module:

- Arguments as a list, never a shell string; `shell=False` always.
- Explicit timeout on every call — no unbounded subprocess calls.
- `capture_output=True`, `check=False`, and explicit, manual return-code handling — don't let
  a non-zero exit raise an uncaught exception where the caller needs a structured failure
  category instead.
- Path/binary resolution follows an explicit, documented precedence (e.g. an explicit CLI
  flag, then an environment variable, then a bare name on `PATH`) — don't hardcode a path.

## Structured logging and output-stream discipline

- Logs are structured key/value calls (e.g. `structlog`-style), not f-string messages.
- Logs go to stderr. Program/scan output goes to stdout. If the tool emits machine-readable
  output (JSON), stdout must stay parseable — nothing else writes there.
- Serialize output via the model's own serialization (`model.model_dump(mode="json")` for
  Pydantic), never a hand-built dict that can drift from the model's actual shape.

## Quality gates (verify-only — this skill runs them locally, it doesn't own the sign-off)

The repo's coding-standards doc has an authoritative Tier-1 gate list and exact thresholds
(coverage percentage, severity thresholds for security scanners) — read it and use its exact
numbers, not the illustrative ones below. The typical shape of a Tier-1 gate set in this
codebase family:

```
ruff check .                          # lint
ruff format --check .                 # format, verify-only — never rewrite without being asked
mypy <package> --strict               # types
pytest --cov=<package> --cov-fail-under=<N>   # tests + coverage floor
bandit -r <package>                   # Python security footguns
pip-audit                             # known-vulnerable dependencies
deptry .                              # unused/undeclared dependencies
reuse lint                            # SPDX header compliance
gitleaks detect --no-git --source .   # secret scan (or trufflehog if unavailable)
```

Run these as part of the normal implementation loop — you should not hand back code you
haven't run these against locally. But note the distinction: running them here is part of
making the code correct before you say "done," not the same thing as a formal PR-readiness
audit. If the user is asking "is this ready to merge" as a distinct question, that's the
reviewing skill's job (`breachsafe-quality-review`), not this one's.

- Do not claim a gate passed without having run it. If a tool is unavailable, say so plainly
  (`NOT RUN: <reason>`) rather than skipping silently or asserting success.
- A coverage-threshold miss is a real signal — add tests, don't lower the threshold to make
  the number pass.
- `ruff format --check .` (not bare `ruff format .`) unless the task is explicitly a
  formatting-only change the user asked for — mechanical formatting and behavior changes stay
  in separate commits per most of these repos' own coding rules.

## Escape hatches — use them explicitly, don't bury them

- `ASSUMPTION: I am assuming X because the spec is silent on it. If wrong, change to Y.` —
  when a spec gap forces a judgment call. Don't invent file paths, function names, or library
  APIs to fill the gap silently.
- `ANTIPATTERN ACCEPTED: <name>, because <reason>` — for an intentional, documented deviation
  from the repo's own anti-pattern rules (e.g. the speculative-generality case above). State
  it in the final response, not just in a code comment.

## Refuse security shortcuts

Refuse — and propose the secure alternative instead of silently complying — for any request
that requires: disabled TLS/certificate verification, `shell=True` with any
externally-influenced input, removed subprocess/network timeouts, logging of secrets,
`eval`/`exec`/`pickle.loads` on untrusted input, or swallowing a security-relevant error. This
applies even when the request is framed as temporary ("just for now," "to make CI green").
