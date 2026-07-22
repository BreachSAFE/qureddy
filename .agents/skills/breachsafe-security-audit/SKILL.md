---
name: breachsafe-security-audit
description: Deepest, highest-stakes audit skill in the BQP library — crypto-correctness (FIPS 203/204, RFC 8446/5869, SP 800-38D), memory/timing side-channel safety (zeroize discipline, unsafe FFI, empirically-measured constant-time), CA-design footguns (privilege escalation, weak serials, CA-key exposure, trust overclaim), key-custody threat modeling against real OS security primitives, fuzzing, and dependency soundness. Audit only — never fixes code, never files an issue/PR/comment/label without explicit user authorization. Use for any security review of QuCrypt, QuCert, QuCustody, or crypto-touching code elsewhere in the BreachSAFE Quantum Platform.
---

# breachsafe-security-audit

The deepest and highest-stakes skill in the BQP skills library. It answers one question:
**"could this code, as written, leak or mishandle a secret, mint a dangerous certificate, or
be forced into undefined behavior?"** — as distinct from "does it match the standard's text"
(that's `breachsafe-conformance`) or "is it clean, tested, well-structured code"
(`breachsafe-quality-review`).

## Stop and read this first: authorization gate

**This skill is audit-only. It never fixes code.** Findings are reported, not patched.

It may read anything (source, tests, docs, `git log`, `gh issue list`) and may **run**
read-only or measurement tooling (`cargo test`, `cargo clippy`, `cargo miri`, sanitizer
builds, `cargo fuzz run`, `dudect-bencher` harnesses, `cargo audit`) because those are
diagnostic, not mutating. It must **never**, on its own initiative:

- edit source, test, or documentation files to "fix" a finding,
- run `gh issue create`, `gh issue comment`, `gh pr create`, or apply/change a label,
- open, push to, or merge a PR,
- commit anything.

Draft the finding (title, body, severity, repro) and show it to the user. Only file it after
the user gives **explicit, in-conversation authorization for that specific finding**. A
general "audit this" request is not standing authorization to file everything you find —
authorization is per finding, requested at report time. This gate is repeated at the top of
every reference file's "what to do with a finding" section; do not let a reference file's
own `gh issue create` example read as pre-authorized.

**Primary-source rule:** any standards claim this skill's checks depend on (an RFC clause, a
FIPS section, an OpenSSL man-page contract, a byte size) must be verified against the
project's own vendored spec text or reference docs at audit time, not asserted from memory.
Where a reference file below states a fact as "sourced ground truth," treat that sourcing as
current as of this file's last verification, not as permanently true — re-check anything
that could have changed (library GA status, OS platform capability, algorithm parameters)
before repeating it in a real finding.

## Stay in its lane

- **Standards/spec citation accuracy, clause-by-clause RFC/FIPS/NIST conformance,
  known-answer-vector testing, X.509 structural conformance** → `breachsafe-conformance`.
  This skill uses standards citations to explain *why* a security anti-pattern is dangerous,
  but does not own "does this cite the standard correctly."
- **General code quality, PR/issue verification workflow, doc-drift, generic
  (non-crypto-specific) anti-patterns** → `breachsafe-quality-review`.
- **Supply-chain tooling enforcement (`cargo audit`/`cargo deny`/`cargo vet` running and
  gating CI), OSS release readiness** → `breachsafe-release`. This skill's
  `dependency-soundness.md` asks a different question — "is this dependency the *right,
  sound* primitive, and are we mixing in something weak or redundant" — not "does the
  advisory-scanning tooling run." The two compose; neither duplicates the other.
- **Sequencing, roadmap, ADR phase-gating** → `breachsafe-pqc-pm`.

## Applies to

| Component | Repo | Scope |
|---|---|---|
| QuCrypt | `breachsafe-crypto-rs` | Full scope. Real Rust crypto code today — every reference file below applies directly. |
| QuCert | `breachsafe-pki-rs` | Full scope. `ca-design-anti-patterns.md` is its primary lane; crypto-correctness, unsafe-FFI, constant-time, and fuzzing apply to its own OpenSSL usage and to CSR/certificate parsing paths (attacker-controlled input); dependency-soundness applies to its own dependency tree. |
| QuCustody | `breachsafe-custody` | No crate code yet. `custody-memory-audit.md` applies **now** as design-review guidance against its ADRs/docs — read it as "does the design commit to claims the OS primitives can back," not "does the code back its claims." Once crate code lands, run it as a full code audit. The other reference files are not-yet-applicable (nothing to grep, nothing to fuzz) until code exists — say so; don't force a pass. |
| QuReddy | `qureddy` | Python, not Rust. `unsafe-ffi-verification.md`, `constant-time-verification.md`, and `fuzzing-protocol.md` (cargo-fuzz specifically) do not apply. `crypto-correctness-checklist.md`'s general framing and `dependency-soundness.md` (weak/legacy-primitive detection, sound dependency choice) apply if/when it links a crypto library directly rather than only scanning external TLS endpoints — check current scope before assuming either applies. |
| Qurum | `quorum` | Python, an inventory/aggregation tool, not a crypto implementation. Same caveat as QuReddy — narrower still, since it doesn't handle key material today. Revisit if that changes. |

## What this skill covers, and where

1. **Crypto-correctness** (FIPS 203/204 sizes, AES-GCM/HKDF wire-format and call-order
   rules, error-handling/secret-hygiene rules, the "thin wrapper — don't reimplement
   OpenSSL" rule, Rust-specific memory-safety and zeroize discipline, an OWASP-crypto
   mapping) → `references/crypto-correctness-checklist.md`
2. **CA-design anti-patterns** (privilege escalation via CSR/issuer trust, weak serials,
   CA-key exposure, path-length misuse, missing proof-of-possession, trust overclaim,
   algorithm downgrade, identity spoofing, god-object design — each mapped to an RFC line
   and a named rcgen/step-ca precedent) → `references/ca-design-anti-patterns.md`
3. **Key-custody threat model** (secure-heap reality, OS key-storage tiers and what they
   actually guarantee, the two-axis at-rest×in-use model, fail-closed negotiation)
   → `references/custody-memory-audit.md` — **includes a corrected Windows ML-DSA
   custody claim; read this file even if you think you already know the old version.**
4. **Constant-time verification** (empirical measurement via dudect-bencher, not just
   grepping for `==`) → `references/constant-time-verification.md`
5. **Unsafe-FFI / undefined-behavior verification** (Miri on the Rust-side glue,
   sanitizers on the real C boundary) → `references/unsafe-ffi-verification.md`
6. **Fuzzing** (targets, harness patterns, triage) → `references/fuzzing-protocol.md`
7. **Dependency soundness** (weak/legacy/duplicate primitive detection, zeroize/subtle
   used correctly, version coherence) → `references/dependency-soundness.md`
8. **Deployment posture** (TEE/confidential-computing, FIPS 140-3 module mode, key-custody
   backend at the server layer — gated N/A until each surface actually exists)
   → `references/deployment-posture.md`

## How to run an audit

1. Identify which component you're auditing and confirm from the table above which
   reference files actually apply — don't run a Rust-only check against a Python repo, and
   don't claim a pass for a surface (custody code, a deployment posture) that doesn't exist
   yet. "Not built" is a valid, honest verdict; it is not the same as "secure."
2. Read the relevant reference file(s) in full before running their commands — several
   encode a specific reason a naive grep is insufficient (constant-time and unsafe-FFI
   especially): read the "why this isn't just a grep" framing, not just the command list.
3. Set up the environment per the target repo's own `CLAUDE.md`/`README` (OpenSSL path,
   toolchain, nightly requirements) — this skill deliberately does not hardcode any of
   that, since it drifts and differs per machine.
4. Run the checks, record PASS/FAIL/N-A honestly per the report format each reference file
   defines, and draft findings — but do not file anything without per-finding
   authorization (see the gate above).
5. Before drafting a new finding, check the target repo's own live open-issue list
   (`gh issue list --repo <owner>/<repo> --state open`) so you don't duplicate one that's
   already tracked. Do not rely on any point-in-time issue-number list embedded in this
   skill — there isn't one, deliberately: a snapshot of issue numbers goes stale the moment
   someone else files or closes one, and a stale snapshot causes duplicate filings or false
   "already tracked" dismissals. The live tracker is the only correct source.

## Honesty rules (cross-cutting, all sections)

- A PASS means "no violation found by the checks actually run," not "proven secure."
  State what was and wasn't covered (this matters most for constant-time and unsafe-FFI
  checks, where partial tool coverage is the normal case, not the exception).
- Never report a pass for a surface that doesn't exist yet (deployment posture, custody
  code before it's written). Say "not built — N/A."
- Never carry forward a specific test pass/fail count, issue-number ledger, or other
  point-in-time snapshot into this skill's own files — re-derive it live, every time, from
  the target repo.
- A compliance-sounding claim (FIPS-validated, hardware-sealed, publicly trusted) that the
  implementation doesn't actually back is itself a high-severity finding, not a nit.
