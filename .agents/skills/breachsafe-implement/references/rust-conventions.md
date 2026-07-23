# Rust conventions — thin-OpenSSL-wrapper discipline

Grounded in `breachsafe-crypto-rs` (QuCrypt / `qucrypt-core`), the concrete example for this
family of crates. The same shape applies to other BQP Rust crates that wrap a vetted external
crypto/protocol implementation (e.g. QuCert's PKI crate) — re-verify the specifics (module
layout, invariants) against that repo's own architecture doc; don't assume crypto-rs's exact
numbers carry over.

## The thin-wrapper rule — the most important constraint

**Do not reimplement anything the underlying library already provides.** These crates add
input validation, wire-format encoding/decoding, output-size assertions, error mapping, and
secret zeroization around library calls — they do not do cryptographic math themselves.

Permitted in `src/`: size guards, RFC/FIPS wire-format struct construction (e.g. an
`HkdfLabel` builder), output size assertions, `Zeroizing<>` wrapping, error-context mapping.

Not permitted: custom AES/SHA/HMAC/KDF logic, custom signature encoding, custom key
generation, cryptographic padding, IV/counter construction in Rust, any loop whose purpose is
a cryptographic transformation. If you catch yourself writing crypto math, stop and find the
library call that already does it. If no safe wrapper exists for a needed operation, write a
thin FFI shim isolated to one dedicated, clearly-named file rather than letting `unsafe`
spread.

## Current module layout (verify against the repo's own architecture doc before trusting this)

`breachsafe-crypto-rs` is a Cargo workspace; the crypto crate lives at
`crates/qucrypt-core/`, not at the repo root. The module structure is split by primitive,
each with a `mod.rs` owning the public functions plus internal submodules:

```
crates/qucrypt-core/
├── src/
│   ├── lib.rs          — crate attrs (#![deny(unsafe_code)]), module wiring, re-exports
│   ├── error.rs         — the crate's error enum + Display/Debug
│   ├── constants.rs      — standards-mandated sizes, shared bounds
│   ├── sign/              — signing primitive: mod.rs + verify.rs + keygen.rs
│   ├── kem/                — key-encapsulation primitive: mod.rs + keygen.rs + ffi.rs (the
│   │                          ONLY file with #[allow(unsafe_code)])
│   ├── aead/                — AEAD primitive: mod.rs + encrypt.rs + decrypt.rs
│   └── kdf/                  — key-derivation primitive: mod.rs + label.rs
├── tests/                — integration-style test crates (unit + property + KAT + e2e)
├── examples/
└── Cargo.toml
```

This crate went through a flat-file → per-primitive-subdirectory reorganization at some
point; older docs and old skill files may still reference flat paths like `src/sign.rs` or
`src/kem_ffi.rs`. Trust `docs/ARCHITECTURE.md`'s "Module Structure" section (or the live
tree) over any older doc that hasn't been updated.

## Non-negotiable invariants — treat as security bugs if broken

The exact set and their values are documented per-crate (check `CLAUDE.md`'s "Critical
invariants" / `docs/ARCHITECTURE.md`) — but the *shape* of what's non-negotiable is
consistent:

- Unsafe code is scoped to exactly one named file per crate (an FFI shim), never spread
  across the crate. The crate-level lint is a `deny`, not a `forbid`, specifically so that one
  file can carry a scoped `#[allow(unsafe_code)]` — don't "fix" this by switching to `forbid`.
- Fixed-size outputs from standards-mandated primitives (signature lengths, key sizes,
  ciphertext/shared-secret sizes) are asserted in code, not just documented. Changing one of
  these numbers is a correctness/security bug, not a refactor — verify against the actual
  standard (FIPS/RFC/NIST doc) before touching it, don't infer from a hazy memory of the spec.
- Secret and derived key material is typed through a zeroize-on-drop wrapper (commonly
  aliased `SecretBytes`), never plain byte vectors. Watch for the gaps zeroize wrappers don't
  cover automatically: stack arrays, `.to_vec()`/`.clone()`-extracted inner buffers, and
  intermediate scratch buffers all need an explicit `.zeroize()` call or an explicit
  `Zeroizing::new(...)` wrap — the wrapper type alone doesn't protect bytes that escape it.
- Operations are fail-closed: an explicit typed error, never a silent fallback, a partial
  result, or a redacted-away detail the caller actually needs.
- Error-disclosure posture (what level of diagnostic detail an error type is allowed to
  surface) is a versioned policy decision (tracked via ADR in crypto-rs) — check the crate's
  current ADR/CLAUDE.md for the live answer rather than assuming either "always redact" or
  "always surface full diagnostics." The one constant across any version of that policy: never
  format secret key material (private keys, shared secrets, derived keys, nonces, plaintext)
  into an error string or a log line, regardless of how verbose errors are allowed to be
  otherwise.

## Library API hazards (runtime failures a type system won't catch)

These are the general shape of hazard you'll hit wrapping a C crypto library from Rust; the
specific call-order requirements are documented per-primitive in the crate's own
`docs/reference/` tree — read the relevant one before touching that primitive:

- **Call-order-sensitive APIs** (e.g. HKDF derive setup) silently produce wrong output on
  reordering, with no compiler warning.
- **AEAD decrypt writes plaintext before verifying the auth tag.** Never return, log, or act
  on a decrypted buffer until the library's finalize call confirms the tag is valid.
- **Contexts/handles must not be reused across independent operations** where the API expects
  a fresh one per call — reuse is a source of subtle wrong-output bugs, not a crash.
- **Implicit-rejection KEMs** (FIPS 203-style ML-KEM) do not error on a tampered
  correctly-sized ciphertext — they return a pseudorandom secret. Tests and callers must
  compare the derived secret against an expected value, not assert on error/success.
- **Signed-vs-unsigned size casts** at FFI boundaries (`usize` → `i32` and similar) can wrap
  silently on very large inputs. Reject oversized inputs before they reach the cast, not after.
- **Hedged (randomized) signatures**: some PQC signature schemes are non-deterministic by
  design — the same key and message produce different signature bytes each call. Never assert
  `sig1 == sig2` in a test for such a scheme; assert both verify instead.

## Toolchain note (macOS)

On macOS with Homebrew OpenSSL, it is not on the default library search path, so every
`cargo` invocation that compiles must set `OPENSSL_DIR`, e.g.:

```bash
OPENSSL_DIR="$(brew --prefix openssl@3)" cargo build
OPENSSL_DIR="$(brew --prefix openssl@3)" cargo test
OPENSSL_DIR="$(brew --prefix openssl@3)" cargo clippy
```

The exact path depends on the machine's Homebrew prefix and the installed OpenSSL major
version — use `brew --prefix openssl@3` (or whatever version the crate's `Cargo.toml`/`build.rs`
requires) rather than hardcoding a literal path. On Linux or with a system-default OpenSSL new
enough for the crate's requirement, `OPENSSL_DIR` may not be needed at all — check the repo's
own build docs first.

## What NOT to do

- No `unwrap()`/`expect()` in library source — use `?` and explicit error mapping.
- No algorithm selection via `&str` parameters — fix the algorithm in the function name/type,
  don't accept a caller-supplied string that could downgrade or typo into the wrong primitive.
- No subprocess calls from crypto library source.
- No second crypto backend alongside the sanctioned one (e.g. no adding a pure-Rust crypto
  crate alongside the OpenSSL wrapper) without an explicit, discussed decision.
- No committing loop/audit-status scratch files (`AUDIT_COMPLETE.txt`, `LOOP_SUMMARY.md`, and
  similar) — write those to a temp location if you need them, don't add them to the tree.
- Don't invent or assume a specific historical test-pass count when reporting status — run
  the suite and report what it says *now*. A number copied from a doc is stale the moment
  someone else's commit lands.

## Issue-referenced workflow (once git-write actions are authorized)

The common convention across these Rust repos: find the governing issue, comment your
intended approach before writing code, reference the issue number in every commit, and close
the issue only after the test suite is green on the target branch — never by comment alone.
This skill can prepare all of that (drafted commit message, drafted issue comment) but does
not execute the git-write or `gh` write actions itself without the authorization described in
the top-level `SKILL.md`.
