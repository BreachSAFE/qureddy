# Generic anti-pattern self-check (Mode 5)

**This is the one mode in this skill that fixes instead of only reporting.** Every other
mode in this skill is audit-only by default. This one is different because the posture
is different: you're checking your **own in-progress, uncommitted** work before you
commit it, not auditing someone else's already-merged code. That's a meaningfully
different situation — there's no independent author to hand findings back to, and
catching your own mistake before it's committed is strictly better than filing it as a
finding against yourself. Fix what you find here, immediately, before committing.

This mode still never pushes, opens a PR, or takes any remote/shared-state action on its
own initiative — "fix your own working tree" stops at the boundary of your local
checkout. Publishing the result still needs the same authorization as anything else in
this skill.

This is the generic, cross-language, non-crypto-specific version of a pre-commit
self-check. Crypto-primitive-specific anti-patterns (unsafe FFI boundaries, nonce reuse,
KDF label correctness, hedged-signature assumptions, memory zeroization of secret
material, timing side channels) are `breachsafe-security-audit`'s checklist, not this
one — if your change touches cryptographic code, run that skill too before committing.

## How to use this

Run every check below against your own diff (uncommitted or staged, not yet pushed). For
each hit, read the surrounding code and decide: real violation, or false positive? Fix
real violations before committing — don't rationalize past a finding just because it's
inconvenient right now. If you find a violation that's pre-existing (not introduced by
your change), it's fine to leave it and note it separately rather than silently fixing
unrelated code in the same commit — but say so.

## 1. Panics, subprocess discipline, logging discipline, dead code/TODOs

Shared with Mode 2 (PR audit) — see `references/generic-code-hygiene.md` for the checks
and grep commands (four categories: panics/aborts, subprocess-outside-shim, stray
logging, dead code/floating TODOs). This mode's posture: **fix what you find**,
immediately, before committing — the opposite of Mode 2's report-only posture, same
underlying checklist (see the authorization-gate section at the top of this file for why
the posture differs).

## 2. Orphan source files

```bash
# Rust: every .rs file under src/ should be reachable from a mod declaration
ls src/**/*.rs
grep -rn '^mod \|^pub mod ' src/lib.rs src/main.rs 2>/dev/null
```

A file that exists on disk but isn't wired into the module tree / package `__init__`
compiles or imports as if it doesn't exist — silently dead code that nobody notices is
dead.

## 3. Unchecked narrowing casts / truncation

```bash
grep -n ' as u8\b\| as u16\b\| as i32\b' src/**/*.rs
```

Every narrowing cast needs either a preceding bounds check or an explicit comment
explaining why truncation can't happen here. An unguarded cast is a silent-corruption
bug waiting for an input that's larger than whoever wrote it assumed.

## 4. Reimplementing something a dependency already provides

Read every function you added or modified. For each one, ask: is this logic that the
crate/library you're already depending on (OpenSSL, the standard library, a vetted
third-party package) already implements safely? Reimplementing algorithmic logic that a
trusted dependency already exposes is both wasted effort and a fresh surface for bugs the
dependency's maintainers already fixed once. This is a general "don't reinvent the wheel"
check — for anything cryptographic specifically, the bar is much stricter and belongs to
`breachsafe-security-audit`.

## 5. Test regression check

```bash
cargo test --lib --tests --quiet 2>&1 | tail -3
# or
pytest --collect-only -q | tail -3 && pytest -q
```

Pass count must be at or above the baseline you captured before starting your change. Any
drop is a regression your change introduced — resolve it before committing, don't commit
first and file a follow-up.

## Report format

```
ANTI-PATTERN SELF-CHECK RESULTS
================================
1. Panics/subprocess/logging/dead-code (generic-code-hygiene.md) : PASS / FAIL (fixed / list remaining)
2. Orphan source files                                            : PASS / FAIL
3. Unchecked narrowing casts                                       : PASS / FAIL
4. Reimplemented dependency logic                                  : PASS / FAIL
5. Test regression                                                  : N passed, M failed (baseline: X)

VERDICT: CLEAN / N VIOLATIONS FIXED BEFORE COMMIT
```
