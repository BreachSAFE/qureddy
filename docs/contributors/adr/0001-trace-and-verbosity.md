# ADR 0001 — `--trace` flag and verbosity refactor

**Status:** Accepted
**Date:** 2026-04-26
**Deciders:** Paul Volosen, project lead
**Consulted:** Claude (review), claude-3-developer (proposal)
**Informed:** Codex
**Supersedes:** none
**Superseded by:** none

---

## Context

The current QuReddy verbosity ladder (`-v / -vv / -vvv`) maps to `WARNING / INFO / DEBUG / DEBUG`. `-vv` and `-vvv` are functionally identical at the log layer. The CLI also emits a duplicate `scan.start` event (one from the CLI before the scanner runs, one from the scanner after `scan_id` is bound), which is observed noise.

Beyond the ladder problem: there is no way for an operator to see what TLS actually did on the wire. The probe always runs `openssl s_client -brief`, which is intentionally terse. For deep PQ debugging — verifying a server's `supported_groups`, watching a downgrade, confirming a hybrid `key_share` — the operator needs the full handshake trace.

claude-3-developer filed a proposal addressing both concerns:

> `scratch/claude-3-developer/MVP-v01/inbox/reviewboard/adr/claude-developer-3-trace-proposal.md`

The proposal recommended:

1. **Three-level verbosity with clamp** — collapse the ladder, fix the `-vv` / `-vvv` collision, add new DEBUG events for parser decisions and policy rule fires, drop the duplicate `scan.start`, log a one-time `verbosity.clamped` notice on `-vvvv+`.
2. **`--trace` as a separate, named flag** — runs a parallel OpenSSL invocation with `-trace`, captures the output as a new `Evidence` record with `evidence_type="tls.handshake.trace"`, renders as a Rich panel on stdout. Composes with `-v`. Display only — never parsed for negotiation decisions.

Claude's initial review recommended **rejecting most of the proposal** for MVP 0.1 on the grounds that `--trace` is scope creep relative to the mvp-implement skill's "no trace fallback parser" exclusion, and that the per-evidence-type `stdout_excerpt` cap change is a JSON schema-stability concern.

Project lead overrode that recommendation with the philosophy:

> "I want --trace for openssl trace more the better."

This ADR records the resulting decision and the calibration choices on the proposal's open questions.

## Decision

**Approve both PRs as proposed, with five conditions.**

### Approved scope

- **PR 1 — Verbosity refactor:**
  - Drop the duplicate `scan.start` from `cli.py`.
  - Add new DEBUG events: `parser.matched`, `parse.rejected`, `policy.fired`. Each new event gets at least one corresponding test in `test_logging.py`.
  - Add `verbosity.clamped` info-once log on `-vvvv+`.
  - Update `--help` text for `-v` to document each level's job.

- **PR 2 — `--trace` flag:**
  - New `run_trace_probe()` in `openssl_probe.py` mirroring the existing probe shape but using `-trace`.
  - Scanner invokes both probes (hybrid + classical) when `--trace` is set; merges the trace outcome as a new `Evidence` record per probe.
  - Console adapter renders a "Handshake trace" panel from the trace evidence.
  - Real `-trace` fixtures captured from `pq.cloudflareresearch.com` AND `example.com`, saved as `tests/fixtures/openssl/trace_*.txt`.
  - JSON output round-trip test confirming trace evidence survives serialization.

### Conditions

**Condition 1 — Lenient `-vvvv+` clamp.**
On `-vvvv` or higher, clamp to `-vvv` and log a one-time `verbosity.clamped` info event with the requested and applied levels. Do not reject with usage error. Matches `kubectl`, `docker`, `cargo` precedent.

**Condition 2 — Both probes traced (hybrid + classical).**
When `--trace` is set, capture the trace for both the hybrid probe and the classical control probe. The difference between the two traces is often what answers the operator's question. Cost: two extra subprocess invocations per scan, ~10-40 KB extra in the JSON. Acceptable trade given opt-in.

**Condition 3 — Add `Evidence.stdout_full: str | None = None` instead of changing `stdout_excerpt` semantics.**

The proposal's recommendation to lift the `stdout_excerpt` 4 KB cap conditionally based on `evidence_type` is rejected. That would change the meaning of an existing field across rows in the same JSON document — a schema-stability break per CODING_RULES Rule 11.4.

Instead: add a new optional field `stdout_full: str | None = None` to the locked `Evidence` model. Populated only for `evidence_type == "tls.handshake.trace"`; `None` for all other evidence types. `stdout_excerpt` keeps its 4 KB cap universally. Downstream JSON consumers see a new optional field and adapt without breakage.

**This requires updating `.claude/skills/mvp-implement/SKILL.md` in the same PR**, per the skill's own rule that adding fields requires updating the skill first.

**Condition 4 — Skill update tightens "no trace fallback parser" exclusion.**

The mvp-implement skill currently lists in its "Excludes":

```
- trace fallback parser
```

This exclusion is preserved but tightened to clarify it's about *parsing*, not *capture or display*. The skill update changes that line to:

```
- trace fallback parser (the -brief parser is canonical; --trace
  output is captured and displayed but never parsed for negotiation
  decisions)
```

And adds to the skill's "Includes" list:

```
- --trace flag for protocol-level handshake visibility (display and
  JSON capture only, not parsed)
```

Both edits go in the same PR as the code changes.

**Condition 5 — `--trace` fires unconditionally regardless of negotiated protocol version.**

The proposal raised the question of refusing `--trace` (or warning loudly) when the server negotiates below TLS 1.3. **Rejected.** `--trace` calls `--trace`. The scanner shows what the wire actually carries.

Rationale:

- The whole point of a TLS scanner is showing what the server actually does. Refusing to show the trace when the server picked TLS 1.2 is hiding the answer to "why is this server not negotiating TLS 1.3 / PQ" — which is exactly the situation where an operator reaches for `--trace`.
- QuReddy is read-only. It does not generate traffic, store keys, or act on the data. The operator gets the trace and reads it.
- TLS 1.2 traces do not expose secrets in the parts that get printed. Pre-handshake bytes are inherently public. Cert chains are public by definition. Encrypted parts stay encrypted. Keys never appear on the wire in any TLS version.
- Adding a refusal here would be paternalism the operator did not ask for.

If a future security review surfaces a real concrete leak in trace output (not a hypothetical), revisit via a new ADR.

## Consequences

### What changes

- `Evidence` model gains one new optional field (`stdout_full: str | None = None`). Additive — does not break existing JSON consumers.
- mvp-implement skill is updated in the same PR (per the skill's "update first" rule). The "Excludes" list tightens; the "Includes" list grows.
- The `-vv` / `-vvv` collision is resolved: `-vv` adds DEBUG event coverage; `-vvv` additionally adds the "Commands run" panel on stdout.
- The duplicate `scan.start` is gone.
- New DEBUG events (`parser.matched`, `parse.rejected`, `policy.fired`) are emitted at `-vv` and `-vvv`. Each is covered by a test.
- A new CLI flag `--trace` is added. Composes with `-v` levels. Adds two extra subprocess invocations per scan when used.
- Operators get a "Handshake trace" panel and the full bytes in JSON when `--trace` is passed.

### What does not change

- Default behavior: no flags, same output as today.
- JSON output for scans without `--trace`: unchanged. `stdout_full` is `None` and Pydantic serializes it as `null` (or omits if `exclude_none=True` is used by the renderer).
- The `-brief` parser contract: parser still consumes `-brief` output exclusively. `--trace` output is never parsed for negotiation decisions.
- The schema_version: stays at `qureddy.scan.v1`. The new field is additive, not a breaking change.
- The `--format`, `--retry-on`, `--retries`, `--retry-delay`, `--openssl`, `--sni`, `--timeout`, `--quiet`, `--json-logs` flags: untouched.
- The OpenSSL boundary: `--trace` invocation lives in `openssl_probe.py` like all other OpenSSL calls.

### What gets harder

- PR 2 is a real PR — probably 200-400 lines of code, plus tests, plus the skill update, plus new fixtures. Not a small change.
- Scan duration with `--trace` roughly doubles (4 OpenSSL invocations vs 2). Operators opt in, but the cost is real.
- JSON payload size grows by ~10-40 KB per scan when `--trace` is passed. Downstream consumers should be prepared.

## Alternatives considered

### Alternative 1: Reject `--trace` for MVP 0.1 (Claude's initial review recommendation)

**Rejected by project lead.** The reasoning was that `--trace` is scope creep relative to the skill's "no trace fallback parser" exclusion. Project lead overrode on the philosophy that more OpenSSL output is better for the tool's core mission.

The skill's exclusion was intended to prevent the *parser* from depending on trace output (a real complexity risk). Capturing and displaying trace output without parsing it is a different feature with different complexity. The skill update in Condition 4 makes this distinction explicit.

### Alternative 2: Lift `stdout_excerpt`'s 4 KB cap conditionally based on `evidence_type` (proposal's recommendation)

**Rejected.** Field semantics changing per row is a schema-stability break in spirit even if the field name and type don't change. Downstream consumers that truncate or size-limit based on the field's documented bound would silently misbehave. Adding a new field (`stdout_full`) is additive and breaks nothing.

### Alternative 3: Refuse `--trace` if protocol negotiates below TLS 1.3

**Rejected.** Paternalism the operator did not ask for. See Condition 5.

### Alternative 4: Bump `schema_version` to `qureddy.scan.v1.1`

**Considered, not chosen.** A version bump is unnecessary because the change is additive (new optional field) rather than breaking. Reserving version bumps for actual breakage keeps the version signal meaningful.

### Alternative 5: Add `--debug-parser` and `--debug-policy` named flags instead of new DEBUG events

**Rejected** (also rejected by the original proposal). Premature flag proliferation. The DEBUG event volume is small (≤10 lines per scan); category gating can be added later if a real user reports the firehose is too loud.

## Implementation order

1. **PR 1 first** (verbosity refactor). No dependency on Condition 3 (no model changes). Lower-risk.
2. **PR 2 second** (`--trace` flag). Depends on Condition 3 (`Evidence.stdout_full`) and Condition 4 (skill update) landing in the same PR.

Both PRs land in `scratch/claude-3-developer/MVP-v01/` for review before any merge into the canonical tree.

## Acceptance criteria

For PR 1 to be considered complete:

- [ ] Duplicate `scan.start` no longer fires
- [ ] `verbosity.clamped` event fires at `-vvvv+`
- [ ] New DEBUG events fire at `-vv` and `-vvv`: `parser.matched`, `parse.rejected`, `policy.fired`
- [ ] Each new event has a test in `test_logging.py`
- [ ] `--help` text updated for `-v`
- [ ] All Tier 1 quality gates pass (ruff, mypy, pytest+coverage, bandit)

For PR 2 to be considered complete:

- [ ] `Evidence.stdout_full` field added; default `None`
- [ ] Skill update lands in the same PR; both Excludes tightening and Includes addition present
- [ ] `run_trace_probe()` exists and is the only new path that calls `openssl s_client -trace`
- [ ] Scanner invokes trace probes for hybrid AND classical when `--trace` is set
- [ ] Trace evidence renders as a Rich panel on stdout
- [ ] Real fixtures captured from `pq.cloudflareresearch.com` AND `example.com`
- [ ] JSON round-trip test confirms `stdout_full` survives serialization
- [ ] CLI smoke test confirms `--trace` adds two trace evidence records (one per probe)
- [ ] All Tier 1 quality gates pass
- [ ] Audit-pr skill output included in the PR description

## References

- claude-3 proposal: `scratch/claude-3-developer/MVP-v01/inbox/reviewboard/adr/claude-developer-3-trace-proposal.md`
- mvp-implement skill: `.claude/skills/mvp-implement/SKILL.md`
- coding rules: `docs/CODING_RULES.md`
- agent anti-patterns: `docs/AGENT_ANTIPATTERNS.md`
- prior code reviews:
  - `scratch/inbox/qa/claude-app/mvp-code-review-v2.md`
  - `scratch/inbox/qa/claude-3-developer/mvp-v01-code-review.md`
  - `scratch/inbox/qa/oss-readiness-comparison.md`

## Change log

- 2026-04-26 — initial decision recorded by project lead. Status: Accepted.
