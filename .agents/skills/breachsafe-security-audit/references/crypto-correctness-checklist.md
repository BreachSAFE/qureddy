# Crypto-correctness checklist (FIPS/RFC + Rust-specific anti-patterns)

**Applies to:** QuCrypt (`breachsafe-crypto-rs`) directly; QuCert (`breachsafe-pki-rs`) for
its own OpenSSL usage and signature/verification paths; framing applies to QuReddy/Qurum
only if/when they link a crypto library directly rather than only scanning externally.

**Audit only — draft findings, file nothing without explicit per-finding authorization from
the user (see SKILL.md's authorization gate).** This file answers "is the crypto usage
correct against the standard and safe against Rust-specific footguns" — it does NOT verify
clause-by-clause RFC/FIPS conformance of the wire format itself (that's
`breachsafe-conformance`) and does NOT run known-answer vectors (also
`breachsafe-conformance`).

## Before you start — verify sizes and algorithm choices against the live source, not memory

FIPS object sizes and the current default/opt-in algorithm tier are exactly the kind of fact
that has drifted before in this codebase family (a previous draft of one skill asserted an
ML-DSA-65 signature size that was wrong by 16 bytes). Read the target crate's own
architecture doc and `constants.rs` (file names vary; search for the size constants) before
asserting a size in a finding. As last verified against QuCrypt's own architecture doc:

| Algorithm | Public/EK | Private/DK | Sig/CT | Shared secret |
|---|---|---|---|---|
| ML-KEM-1024 (NIST L5, default) | EK 1568 | DK 3168 | CT 1568 | SS 32 |
| ML-KEM-768 (NIST L3, opt-in)  | EK 1184 | DK 2400 | CT 1088 | SS 32 |
| ML-DSA-87 (NIST L5, default)  | pub 2592 | priv 4896 | sig 4627 | — |
| ML-DSA-65 (NIST L3, opt-in)   | pub 1952 | priv 4032 | sig **3309** | — |

QuCrypt ships **both** tiers as first-class functions (a `*_1024`/`*_87` and a
`*_768`/`*_65` variant of every primitive) — Level-3 support is intentional, not migration
residue. A checklist item written as if only one tier exists will miss half the surface;
verify both variants.

HKDF's hash is **not fixed across this codebase's history** — an earlier design assumed
SHA-256; the shipped implementation uses **SHA-384** (`HKDF_HASH_LEN = 48`). Verify the
actual hash against the crate's own `constants.rs` before writing a PRK-minimum-length or
output-maximum finding; do not assume either SHA-256 or SHA-384 from memory or from an older
doc.

## ML-DSA (FIPS 204) — signing/verification

- [ ] Signature size assertion matches the constant actually declared for that tier (see
      table above), enforced on **both** the signing and verification path — a check present
      in only one direction is a partial fix, not a real one.
- [ ] Doc comments do NOT say ML-DSA signing is "deterministic." OpenSSL 3.6's ML-DSA
      signing is **hedged** (FIPS 204 §3.5.1 / Appendix C — random value mixed into the
      nonce): two `sign` calls on the same key + message produce **different** signature
      bytes. Any test asserting `sig1 == sig2` is wrong; it must assert `sig1 != sig2`
      (verify each independently instead). A doc/comment/test that assumes determinism is a
      finding even if no test currently fails on it.
- [ ] No `unwrap()`/`expect()` on an OpenSSL `Result` in the signing/verification path.
- [ ] The signing function accepts a typed key (`PKey<Private>` or the crate's own key
      type), not raw bytes with an implicit format assumption.
- [ ] Verification returns a verification-failure variant (not a generic key-error variant)
      for a bad signature — check the doc comment and the actual returned variant agree;
      these have drifted apart from each other in this family before.
- [ ] Upper message-size guard present (DoS bound) on both sign and verify.

## ML-KEM (FIPS 203) — encapsulation/decapsulation

- [ ] Public key, ciphertext, private key, and shared-secret sizes match the table above for
      whichever tier the function targets.
- [ ] Shared secret is returned as the crate's zeroizing secret type (e.g.
      `Zeroizing<Vec<u8>>`), never a plain `Vec<u8>` — see the Memory & zeroize section below.
- [ ] No subprocess calls to an `openssl` binary anywhere in the library source — all crypto
      goes through the linked OpenSSL library via FFI/the `openssl` crate, never a shelled-out
      CLI call.
- [ ] Implicit rejection (FIPS 203's IND-CCA2 property): a tampered ciphertext of the
      *correct length* must NOT produce an `Err` — it produces a different (wrong) shared
      secret. A test or code path that treats a tampered ciphertext as an error condition
      misunderstands the primitive; flag it.
- [ ] The `EVP_PKEY_CTX` (or equivalent context) is freshly created per operation, never
      reused across encapsulate/decapsulate calls.

## AES-256-GCM (NIST SP 800-38D)

- [ ] Nonce is 12 bytes, generated via a CSPRNG call (never hardcoded, never a counter
      without an explicit reuse-prevention argument documented at the call site).
- [ ] Output format is `nonce(12) || ciphertext || tag(16)` (or whatever the crate's own
      documented layout is — verify it's actually followed, don't assume this exact layout
      for a different repo).
- [ ] Minimum-input-length check on decrypt (nonce + tag overhead) before any buffer slicing.
- [ ] **Tag ordering, verified by reading the actual call sequence, not assumed:**
      - Decrypt: `SET_TAG` (or the crate's binding) is called **before** the update/decrypt
        call, not after — OpenSSL requires the tag before processing ciphertext.
      - Decrypt: the finalize call is where authentication actually fires. Any plaintext
        produced by the update call before finalize succeeds is **unauthenticated** — it
        must never be returned, logged, or used if finalize fails. A code path that returns
        partial plaintext on a finalize error is a stop-the-line finding.
      - Encrypt: `GET_TAG` is called **after** finalize, never before — the tag isn't
        computed until finalization.
- [ ] AAD (if used) is passed with a `None`/null output buffer — GCM produces no ciphertext
      bytes for AAD.
- [ ] Integer-width hazard: the underlying C API's length parameter is a signed 32-bit int.
      A `usize → i32` cast on an input near/above 2 GB wraps silently. The library must
      reject oversized input **before** that cast, with an explicit size guard — don't rely
      on the cast itself to fail safely.

## HKDF (RFC 8446 §7.1 / RFC 5869)

- [ ] Label prefix matches the RFC 8446 constant exactly (`"tls13 "` — 6 bytes, lowercase,
      trailing space) if the crate implements TLS 1.3's `HKDF-Expand-Label`. A different
      string (including the tempting-looking literal `"HKDF-Expand-Label"`, which is a
      *description*, not the wire prefix) is a protocol violation.
- [ ] Wire-format `HkdfLabel` construction (length + label_len + label + context_len +
      context) matches RFC 8446 §7.1 exactly — length-prefix each field, don't concatenate
      raw strings.
- [ ] `label.len()` and `context.len()` are bounds-checked (`< 255`) **before** any
      narrowing cast to `u8`, not silently truncated by the cast.
- [ ] Any narrowing cast to `u16` (e.g. an output-length parameter) is bounds-checked
      (`<= 65535`) before the cast.
- [ ] PRK minimum length is checked against the hash's actual output size (see the "verify
      against `constants.rs`" note above — do not hardcode 32 for SHA-256 without checking).
- [ ] HKDF mode is set to expand-only (not extract-and-expand) when the input is already an
      extracted PRK — check the actual mode constant passed, not just that *some* mode is set.
- [ ] Any DoS-guard threshold on info/context length is reachable (not set above the
      protocol's own hard maximum, which would make the guard dead code — see Pattern 1
      under Regression patterns below).

## Error handling and secret hygiene

- [ ] **Never** format key bytes, nonces, IVs, seeds, or plaintext into an error message,
      `Debug` output, `format!`, `println!`, or log call — this is the one rule that holds
      regardless of a project's chosen error-disclosure policy.
- [ ] Verify the crate's *current, stated* error-disclosure policy before flagging OpenSSL
      diagnostic detail in errors as a leak. Policies differ and change over time within this
      codebase family: one component's stated v1.0 policy deliberately surfaces full OpenSSL
      diagnostics (error codes, library/function/reason, file:line) for debuggability — this
      is an intentional, documented choice (compare to OpenSSL/OpenVPN/AWS SDK posture), not
      a redaction failure, and OpenSSL's own error codes contain no key bytes. Check the
      target repo's own current documented policy (its `CLAUDE.md` or `SECURITY.md`) rather
      than assuming redaction is required — but the "never format secret key material" rule
      above applies unconditionally regardless of which disclosure policy is in force.

## API surface

- [ ] No algorithm name accepted as a caller-controlled `&str` or similar stringly-typed
      parameter anywhere reachable from outside the crate (`fn sign(algorithm: &str, ...)` is
      the anti-pattern; `fn sign_mldsa65(...)` — algorithm fixed in the function name or a
      closed enum — is correct). A string-typed algorithm parameter lets a caller downgrade
      to a weak or wrong primitive.
- [ ] No `Command::new`/`std::process::*` calls anywhere in the library source — no
      shelling out for crypto operations.

## Thin-wrapper rule (where applicable — verify the target crate actually follows this
architecture before applying it)

Some components in this family are explicitly a *thin wrapper* around OpenSSL: no
cryptographic transformation is meant to be written in Rust — every primitive operation goes
through an audited OpenSSL EVP call, and Rust-side code is limited to guards, wire-format
struct construction, and secret-type wrapping. Verify the target repo actually states this
architecture (check its `CLAUDE.md`) before applying it — don't assume every BQP component
is a thin wrapper.

Where it applies:
- [ ] No custom AES/SHA/HMAC/KDF/signature-encoding logic written in Rust — OpenSSL provides
      all of it.
- [ ] No cryptographic padding, IV/counter construction, or modular-arithmetic loop in `src/`.
- [ ] Permitted, not a violation: input size guards, RFC wire-format struct construction
      (e.g. `HkdfLabel`), output-size assertions, secret-type (`Zeroizing<>`) wrapping, error
      mapping.
- [ ] A `for` loop in crypto-adjacent code whose purpose is a cryptographic transformation
      (not just formatting/collecting) is a candidate violation — read it and decide.

## Memory & zeroize discipline (Rust-specific)

- [ ] Every `Vec<u8>` (or equivalent heap buffer) holding a shared secret, derived key, or
      private-key byte sequence is the crate's zeroizing secret type
      (`Zeroizing<Vec<u8>>`/equivalent), not a plain `Vec<u8>`.
- [ ] Stack arrays holding key/nonce/tag material (`let mut buf = [0u8; N]`) are explicitly
      `.zeroize()`d before the binding drops, or constructed as `Zeroizing::new([0u8; N])`
      from the start. `Zeroizing<Vec<u8>>` does **not** automatically cover stack arrays or
      freshly-allocated intermediate `Vec`s created inline (e.g. a GCM tag buffer) — each of
      those needs its own explicit zeroize.
- [ ] `.clone()` on the crate's zeroizing type stays zeroizing (verify the type actually
      implements `Clone` in a way that preserves the wrapper). `.to_vec()` / `.as_slice().to_owned()`
      / any method that extracts the *inner* `Vec` produces a plain, non-zeroized copy — flag
      any such extraction of secret bytes.
- [ ] Key material is never passed or returned as `String` — `String` has no
      `ZeroizeOnDrop`; convert to the zeroizing byte type instead.
- [ ] A hand-rolled zero-out loop (`for b in &mut buf { *b = 0 }`) on secret bytes is
      **not sound** — the compiler's dead-store elimination can remove it since the write is
      never subsequently read. This is a "reinvented zeroize, and reinvented wrong" finding,
      not a style nit; the `zeroize` crate's `write_volatile` + compiler fence is the only
      sound pattern here. Don't let this compose with a "don't reimplement crypto" finding —
      it's actually a *different* bug (unsound scrubbing) worth its own finding.

## Parameterized-function and integer-cast anti-patterns

- [ ] No hash-algorithm name accepted as `&str` (`fn expand(hash: &str, ...)` would let a
      caller request e.g. MD5 in production).
- [ ] Size constants are declared `const`, not `let` — a `let`-bound "constant" can shadow or
      be reassigned; a `const` cannot.
- [ ] Every `as u8` / `as u16` / narrowing numeric cast in a crypto-adjacent path has a
      preceding bounds check (or a comment justifying why truncation is safe) — a cast
      without one is a silent-truncation bug, and this class of bug has recurred in this
      codebase family as a *regression* even after being fixed once (see Pattern 3 below).
- [ ] No `match` on an algorithm/mode string without an exhaustive or explicit-error default
      arm.

## Stop-the-line list (Rust crypto specific)

File as CRITICAL (after drafting and getting authorization) if found in library source:

1. `unwrap()`/`expect()` on an OpenSSL `Result`.
2. `panic!` outside test code — a crypto library must never panic on attacker-controlled
   input; it returns a typed error.
3. `==`/`!=` comparison on any MAC, derived key, shared secret, signature, or auth token —
   timing side-channel; see `constant-time-verification.md`.
4. Algorithm name accepted as a caller-controlled string parameter.
5. Shared-secret or key bytes returned as a plain (non-zeroizing) `Vec<u8>`.
6. `unsafe` outside the crate's designated FFI shim module (verify the current module path —
   it has moved before within this codebase family, e.g. from a flat `src/kem_ffi.rs` to a
   per-primitive `src/kem/ffi.rs`; check `lib.rs`'s module wiring and the architecture doc
   rather than assuming a path from an older skill or doc).
7. Key material, nonces, or plaintext visible in any error message, `Debug` output, or log
   line (independent of the disclosure-policy caveat above).

## OWASP mapping (Rust-specific angle)

| OWASP | Rust-specific check | How |
|---|---|---|
| A01 Broken Access Control | Auth tokens compared with `==` not constant-time | grep + measure |
| A02 Cryptographic Failures | Weak algo, hardcoded key/nonce, variable-time compare | grep + audit |
| A03 Injection | Format string built from user input passed into a crypto/FFI call | grep |
| A04 Insecure Design | Algorithm chosen via caller parameter instead of fixed in the API | review |
| A05 Security Misconfiguration | `deny`/`forbid(unsafe_code)` missing or weakened | grep |
| A06 Vulnerable Components | `cargo audit` clean | see `dependency-soundness.md` and `breachsafe-release` |
| A07 Auth Failures | Cross-key verification untested (wrong key accepted) | test |
| A08 Software/Data Integrity | `Cargo.lock` not committed / not honored in CI | repo check |
| A09 Logging Failures | Key bytes reachable in any log line | grep |
| A10 SSRF | Usually N/A for a crypto library with no HTTP client | — |

## Regression patterns worth checking every audit

These are patterns that have recurred (not hypothetical) in this codebase family as fixes
land elsewhere — check for them every time, independent of what changed:

1. **Dead guard.** A DoS/size guard is added at one layer, but a lower layer has a stricter
   hard limit that fires first, making the new guard unreachable dead code. Check: every
   guard threshold must be `<=` the smallest hard limit below it in the call stack.
2. **Partial sanitization.** A security property (error redaction, zeroization) is applied
   to one output path (e.g. `Display`) but not a sibling path (`Debug`, log, HTTP body).
   Enumerate every output path for the property and check each one.
3. **Integer-width mismatch.** A guard/constant is defined at one width (`usize`/`u32`) then
   cast to a narrower type (`u16`/`u8`) later without a bounds check — grep for `as u8`/
   `as u16` and confirm each has a preceding check.
4. **Orphan files.** A file added under `src/` that isn't declared as a `mod` in `lib.rs` is
   never compiled — silently dead code that audits (and the compiler) won't catch by reading
   alone.
5. **Test name/semantics mismatch.** A test named for one algorithm/size/condition that
   actually exercises a different one passes silently while hiding that the named case is
   untested.

## What to do with a finding

**Audit only. Draft, don't file.** Per the authorization gate in `SKILL.md`, draft the
finding (quote the exact code with file:line, state the impact, propose a verification
command) and present it to the user. File it (`gh issue create` or equivalent) only after
the user explicitly authorizes that specific finding. Check the live open-issue list first
to avoid duplicates — do not trust any issue-number list embedded in a skill file.
