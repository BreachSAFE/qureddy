# Fuzzing setup and triage

**Applies to:** QuCrypt (wire-format parsing, size guards) and QuCert (CSR/certificate
parsing, DN/SAN parsing — anywhere untrusted bytes reach a parser). Not applicable to
QuReddy/Qurum today (no cargo-fuzz target; if either starts parsing untrusted binary input
directly, revisit).

**Audit only — if fuzzing finds a crash, draft a finding; do not fix it inline, and file
nothing without explicit per-finding authorization from the user (see SKILL.md's
authorization gate).**

## When to use

- After adding or changing any size guard.
- After changing wire-format or ASN.1/DER parsing (HKDF label encoding, AEAD nonce/tag
  extraction, CSR/certificate parsing, DN/SAN parsing).
- Before a release.
- Any time a new input path from untrusted bytes is added.

## What to fuzz — by component

**QuCrypt-shaped targets** (adjust function/module names to the current crate — verify
against its own source, these are illustrative):

| Target | Why | Guards exercised |
|--------|-----|-------------------|
| HKDF expand-with-label | variable-length label + context + output-length input | RFC 8446 §7.1 label bounds, narrowing-cast guards |
| AEAD decrypt | arbitrary ciphertext | minimum-length check, tag check, upper-size guard, integer overflow |
| AEAD encrypt | arbitrary plaintext | `checked_add` guard on tag-length addition, upper-size guard |
| Signature verify | arbitrary message/signature bytes | upper message-size guard, wrong-length signature handling |
| KEM encapsulate | arbitrary public-key bytes | exact-size check, rejection of wrong sizes |
| KEM decapsulate | arbitrary private-key + ciphertext bytes | exact-size checks, implicit-rejection behavior (must not panic or error on a wrong-length-but-plausible input — see the FIPS 203 note in `crypto-correctness-checklist.md`) |

**QuCert-shaped targets** — CA-design footguns in `ca-design-anti-patterns.md` are
specifically the kind of thing a well-chosen fuzz corpus finds that a hand-written test
misses:

| Target | Why | Guards exercised |
|--------|-----|-------------------|
| CSR parse | attacker-controlled PKCS#10 bytes | RFC 2986 structural bounds, proof-of-possession verification path (A4) |
| Certificate parse (`from_pem`/`from_der`) | attacker-controlled X.509 bytes | round-trip symmetry (A15), extension parsing bounds |
| DN/SAN construction from untrusted strings | identity-spoofing surface | control-character / bidi-override / invisible-character rejection (A13) — a fuzz corpus is a much better way to find a missed code-point range than a hand-picked test list |
| `verify_chain` on a crafted chain | path-validation logic | pathLen enforcement (A9), non-CA-anchor rejection (A10) |

## Setup

```bash
cargo install cargo-fuzz
rustup install nightly
# Run from the crate root. Set env vars the target repo's own CLAUDE.md requires for a
# compiling cargo invocation (e.g. an OpenSSL path) before running any fuzz command.
```

## Initialize the fuzz directory (first time only)

```bash
cargo +nightly fuzz init
```

Creates `fuzz/Cargo.toml` and `fuzz/fuzz_targets/`. If the crate needs a special env var to
compile, make sure it's set for every fuzz invocation, not just `cargo build`.

## Write a fuzz target

Example shape (adapt names/types to the actual function signature — don't copy this
verbatim into a crate whose API has moved):

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split `data` into whatever inputs the target function needs. Keep the split logic
    // itself panic-free (use `.get()`, `saturating_sub`, etc.) — a panic in the harness's
    // own input-splitting code is a fuzzer-harness bug, not a finding about the library.
    if data.len() < 32 { return; }
    let (a, rest) = data.split_at(32);
    // ... call the real function under test here ...
    // The library function itself must never panic — only Ok(..) or a typed Err(..) are
    // acceptable outcomes for any input, however malformed.
});
```

## Run a target

```bash
cargo +nightly fuzz run <target_name> -- -max_total_time=60 -jobs=4
```

## Interpret results

- **No crash** → pass, the guards held for the inputs explored in this run. Note the
  duration/iteration count; a 60-second run is a smoke test, not exhaustive coverage.
- **Crash / OOM / SEGFAULT** → `cargo-fuzz` writes a minimized reproducer to
  `fuzz/artifacts/<target>/`. Reproduce it:
  ```bash
  cargo +nightly fuzz run <target_name> fuzz/artifacts/<target_name>/crash-<hash>
  ```

## What a crash means

| Symptom | Likely cause | Severity |
|---------|-------------|----------|
| `panic at 'attempt to add/multiply with overflow'` | missing `checked_add`/`checked_mul` | security finding — a crypto/PKI library must never panic on attacker input |
| `panic at index out of bounds` | missing size guard or off-by-one | security finding |
| `SEGFAULT` inside a linked C call | FFI contract violated (wrong size/length passed) | stop-the-line — see `unsafe-ffi-verification.md`, this likely means the FFI shim's contract is actually broken, not just the fuzz harness |
| `panic at 'assertion failed'` | an `assert!`/`debug_assert!` reachable on attacker-controlled input | security finding — must be a typed `Err(...)` instead |

**A panic anywhere in library source reachable from untrusted input is always a security
finding, not a low-severity nit.** The library must return `Err(...)`, never panic, on any
input shape.

## After fuzzing

If a corpus of interesting inputs was generated and the user wants it kept, propose adding
`fuzz/corpus/<target>/` to the repo — a committed corpus means future fuzz runs start from
known-interesting inputs. This is a repo-state change; get authorization before committing
it, same as any other artifact this skill produces.

## What to do with a finding

**Audit only. Draft, don't file.** Include the target name, the minimized reproducer (raw
bytes or base64), the exact panic/crash output, the impact (panic = DoS at minimum; a SEGFAULT
inside a linked C call may indicate a real out-of-bounds write, escalate accordingly), and the
exact commands to reproduce. Present it to the user; file it only after explicit per-finding
authorization. Check the target repo's live open-issue list first.
