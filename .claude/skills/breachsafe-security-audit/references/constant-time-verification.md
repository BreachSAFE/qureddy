# Constant-time verification (measure, don't assume)

**Applies to:** QuCrypt and QuCert (Rust components with secret-dependent comparisons or
control flow). Does not apply to QuReddy/Qurum (Python, no cargo toolchain).

**Audit only — draft findings, file nothing without explicit per-finding authorization from
the user (see SKILL.md's authorization gate).**

`crypto-correctness-checklist.md`'s stop-the-line list and grep-based checks catch `==` used
directly on secret material. That catches the obvious source-level pattern but **cannot
prove** constant-time behavior: the Rust/LLVM optimizer can introduce a secret-dependent
branch even when the source looks branch-free, and even a `subtle`-style constant-time
comparison can be undermined by inlining or optimization in some configurations. This file
**measures** timing distributions to verify the property holds in the actual compiled
binary — the grep is necessary, not sufficient.

**Why release mode:** debug builds disable the optimizations that both *cause* and
sometimes *mask* timing leaks. Always measure in `--release`. A debug-mode timing result is
not evidence either way.

## Setup

```bash
# Run from the crate root. Set OPENSSL_DIR (or equivalent) per the target repo's own
# CLAUDE.md if the build can't find its crypto backend.
cargo install dudect-bencher 2>/dev/null || true   # crates.io: dudect-bencher
```

If the measurement tool can't be installed on this toolchain, **stop and say so explicitly**
— draft an infrastructure finding requesting it be added to dev-dependencies/CI. Do not
silently skip the measurement and report a PASS; that is the exact "assume, don't verify"
failure mode this file exists to prevent.

## What to measure

Any operation whose timing could depend on secret bytes:

| Operation class | Secret input | A leak would reveal |
|---|---|---|
| KEM decapsulate | private key, ciphertext | whether the implicit-rejection path (FIPS 203 IND-CCA2 property) is actually constant-time |
| Signature verify | (signature itself is public, but) | an early-out on length/format that depends on secret state, if any exists |
| Any zeroizing-secret-type equality check | shared secret, derived key | byte-by-byte comparison position |
| AEAD tag comparison | tag | usually delegated entirely to the linked crypto library (e.g. OpenSSL) — note that delegation explicitly in the report rather than re-testing what you didn't write |
| CA/custody key comparison or lookup by fingerprint | key material | whether a lookup/compare leaks position of the first mismatched byte |

Most primitive-level timing safety (modular reduction, etc.) is the linked crypto library's
responsibility, already audited upstream. This file's target is the **wrapper-introduced**
comparisons and any Rust-layer secret-dependent control flow — the part the wrapper actually
owns and could get wrong even if the underlying primitive is sound.

## Step 1 — enumerate secret-dependent comparisons

```bash
grep -rn 'ct_eq\|ConstantTimeEq\|== \|!= ' src/ examples/ \
  | grep -iE 'secret|shared|ss\b|key|tag' | grep -v '\.len()'
```

For each hit: is it actually comparing secret bytes? If yes, and it uses `==`/`!=` rather
than a constant-time comparison primitive, that's a candidate leak — measure it in Step 2–3.
If it already uses a constant-time primitive, measure it anyway at least once per audit
cycle — the whole point of this file is that "uses the right API" is not proof by itself.

## Step 2 — write a throwaway measurement harness

Put it under `benches/` or a scratch binary target — it is an audit instrument, not a
project test, and should be deleted after use (Step 4).

```rust
// benches/ct_probe.rs — THROWAWAY, delete after the audit
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::Rng;

fn ct_secret_eq(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Class::Left  = inputs matching a fixed reference
    // Class::Right = random inputs
    let reference = [0x42u8; 32];
    for _ in 0..100_000 {
        let (class, input) = if rng.gen::<bool>() {
            (Class::Left,  reference)
        } else {
            (Class::Right, rng.gen::<[u8; 32]>())
        };
        runner.run_one(class, || {
            // Replace with a call into the ACTUAL wrapper comparison/operation under
            // test — e.g. a function that compares a decapsulated secret to `reference`.
            std::hint::black_box(input == reference)
        });
    }
}

ctbench_main!(ct_secret_eq);
```

## Step 3 — run in release and read the t-statistic

```bash
cargo run --release --bench ct_probe -- --continuous ct_secret_eq 2>&1 | tail -20
```

- **`|t| < 10` and stable across many samples** → no measurable leak for this operation at
  this sample count. Report as PASS, but state the sample count — this is "no leak measured,"
  not "proven constant-time."
- **`|t|` grows past roughly 10 and keeps growing with more samples** → measurable timing
  dependence. Draft a finding with the operation name, the t-statistic, the sample count, and
  the exact harness used to reproduce it.

Run on a quiet machine — CPU frequency scaling and other system load inflate noise. Prefer
many samples over a single short run; a short run with a borderline `|t|` is inconclusive,
not a pass.

## Step 4 — clean up

Delete the throwaway harness. Do not commit it as a project test. If a permanent CT
regression test seems worth having, draft a finding proposing it rather than adding it
yourself — that's a fix, and this skill doesn't make fixes.

## What to do with a finding

**Audit only. Draft, don't file.** State the exact operation (file:line), the tool used, the
t-statistic and sample count, the reproduction harness, and the impact (an attacker measuring
response time can potentially recover secret bytes — CWE-208 / OWASP A02). Present it to the
user; file it (`gh issue create` or equivalent) only after explicit per-finding
authorization. Check the target repo's live open-issue list first.

## Honesty rules

- A PASS means "no leak measurable at N samples on this machine," not "proven
  constant-time." Always report the sample count alongside any PASS.
- Never claim constant-time behavior from a source-level grep alone — that's the exact
  assume-don't-verify trap this file exists to close.
- A timing measurement taken in debug mode is meaningless. Only `--release` results count;
  say explicitly if a result came from debug mode by mistake and re-run before reporting.
