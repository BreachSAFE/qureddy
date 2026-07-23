# Crypto-dependency soundness

**Applies to:** QuCrypt and QuCert (each has its own dependency tree to audit). Framing
applies to QuReddy/Qurum only if/when either links a crypto library directly.

**Audit only — draft findings, file nothing without explicit per-finding authorization from
the user (see SKILL.md's authorization gate).**

`breachsafe-release`'s supply-chain tooling answers "is any dependency vulnerable or
unvetted" (`cargo audit`/`cargo deny`/`cargo vet` running and enforced in CI). **This file
answers a different question: is each crypto-relevant dependency the right primitive, sound,
current, and used correctly — and are we accidentally mixing in a weak or redundant one?** A
dependency can be advisory-clean and still be the wrong or misused tool. The two checks
compose; neither replaces the other — don't duplicate `breachsafe-release`'s advisory-status
findings here, and don't let this file's soundness findings substitute for actually running
`cargo audit`/`deny`/`vet`.

## Setup

```bash
# Run from the crate root — adjust the Cargo.toml path per which component you're auditing
# (QuCrypt and QuCert have their own, separate dependency trees).
```

## Step 0 — identify the crypto-relevant dependencies for this crate

Don't assume a fixed dependency list — read the crate's own `Cargo.toml` and its own
architecture doc. As a shape to expect (verify against the actual file, this varies per
component and drifts over time): the crypto/FFI backend crate and its `-sys` binding, a
pointer/trait-identity crate used at the FFI boundary, the zeroizing-secret crate, and a
constant-time-comparison crate (often dev-only, used in examples/tests).

## Step 1 — one backend only (no mixed primitives)

If the target component's stated architecture is "one crypto backend, no second
implementation" (verify this against the crate's own `CLAUDE.md`/architecture doc — don't
assume it for every component), check:

```bash
grep -rEi 'ring|rustcrypto|aes-gcm|sha2|sha3|hmac|hkdf|ml-kem|ml-dsa|pqcrypto|aws-lc|dalek|p256|k256|rsa =' \
  <path/to/Cargo.toml> Cargo.lock | grep -v '<the crate's own name>\|<the stated backend crate>'
```

- [ ] No second pure-Rust crypto implementation is present in the dependency tree
      alongside the stated single backend.
- [ ] No second AES/SHA/HKDF/KEM/signature implementation is reachable from application
      code — a dependency being present in the lockfile only as an indirect, unreachable dep
      of something else is a different (lower) severity than it being actually wired up and
      callable.
- [ ] A dependency the architecture doc says was deliberately removed (check its own
      changelog/issue history) is confirmed actually absent from both `Cargo.toml` and
      `Cargo.lock`, not just from `Cargo.toml`.

## Step 2 — the zeroizing-secret crate is sound and actually used for secrets

The zeroizing crate itself is a correct, well-audited choice for memory scrubbing — but it
only protects values that actually go through it. Verify the guarantee is real, not assumed
(this overlaps with, and is the dependency-choice half of,
`crypto-correctness-checklist.md`'s Memory & zeroize section — that file asks "is it used
correctly everywhere," this step asks "is the crate itself the right choice, current, and
correctly featured"):

- [ ] The crate's secret-type alias (e.g. `SecretBytes`) actually wraps the zeroizing type,
      and every secret output (shared secrets, derived keys, private-key bytes) is typed
      through it — spot-check, don't just trust the type alias exists somewhere unused.
- [ ] The zeroizing crate has the feature flag enabled that makes heap (`Vec`) zeroizing
      actually work (commonly an `alloc` or `std` feature) — without it, the crate may only
      cover fixed-size stack types.
- [ ] No `.to_vec()`/`.clone()`-then-extract pattern pulls an unprotected plain copy out of
      a zeroizing wrapper (see the corresponding check in
      `crypto-correctness-checklist.md`).
- [ ] The crate version in use is a current, non-yanked line.
- [ ] A hand-rolled zero-out loop anywhere in the codebase is flagged as "don't reinvent
      the zeroizing crate" — it uses `write_volatile` plus a compiler fence internally, which
      a naive loop does not get for free (also covered in
      `crypto-correctness-checklist.md`; if you find one, it's the same finding from either
      angle — don't file it twice).

## Step 3 — constant-time comparison crate is used wherever secrets are compared

- [ ] Every secret/shared-secret/derived-key/MAC/token comparison anywhere in the codebase
      (not just `src/`, check `examples/`/`tests/` too — an example demonstrating a timing
      leak is still a real teaching-the-wrong-thing problem) uses the constant-time
      comparison crate, never `==`/`!=`.
  ```bash
  grep -rn '==' src/ examples/ | grep -iE 'secret|shared|derived|prk|\bss\b' | grep -v '!='
  ```
- [ ] The constant-time crate's version is current.
- [ ] Cross-check any hit found here against `constant-time-verification.md` — a grep hit
      here is a *candidate*, empirically measure it there before treating it as confirmed.

## Step 4 — sys/binding version coherence

Mismatched versions between a high-level crypto crate and its low-level `-sys`/FFI-adjacent
binding crate is a real mixing hazard — it can cause trait-identity breakage or link against
an unexpected ABI version.

```bash
for c in <crypto-crate-name> <crypto-crate-name>-sys <ffi-adjacent-crate> <zeroize-crate> <ct-compare-crate>; do
  echo -n "$c: "; grep -A1 "name = \"$c\"" Cargo.lock | grep version | head -1
done
```

- [ ] The `-sys` binding's resolved version is one the high-level crate actually supports —
      not pinned to a stale or incompatible version by an override elsewhere in the lockfile.
- [ ] Any trait-identity-sensitive crate (e.g. one providing a pointer/handle trait used
      directly at an FFI boundary) resolves to the *same* version the high-level crate
      re-exports/expects — a version mismatch here can silently produce two incompatible
      trait implementations that happen to compile.
- [ ] `Cargo.toml` pins agree with what `Cargo.lock` actually resolves — version drift
      between the two is a distinct, separately-worth-flagging issue from the sys/binding
      mismatch above.

## Step 5 — deprecation / maintenance / EOL

- [ ] None of the crypto-relevant dependencies are yanked, deprecated, or unmaintained —
      cross-check `cargo audit` output and each crate's current crates.io/repo status.
- [ ] The crypto backend crate line in use is actively maintained, not an abandoned fork.
- [ ] No wildcard (`*`) or overly-wide version requirement on any crypto-relevant
      dependency — reproducibility matters more here than for an ordinary dependency.
- [ ] `Cargo.lock` is committed to the repo (verify, don't assume).

## Step 6 — feature hygiene

- [ ] No dependency feature flag enables a legacy/weak algorithm that then becomes
      reachable from application code.
- [ ] The zeroizing crate's enabled feature set is minimal — no unintended
      `derive`/`serde` (or similar) feature pulling in extra weight or surface for no reason.
- [ ] Any test-only or feature-gated API (e.g. a fixed-nonce testing mode) is verified to
      gate *only* the intended narrow behavior — it must not, as a side effect, enable a
      weaker crypto path reachable outside of tests.

## What to do with a finding

**Audit only. Draft, don't file.** Cite the exact dependency and line, state whether it's a
soundness issue (weak/duplicate primitive, unsound zeroize/compare, `==` on secrets) or a
coherence/hygiene issue (version mismatch, wide version requirement, dead feature). Do not
duplicate a `breachsafe-release` advisory-status finding — cross-reference it instead if
one already exists for the same dependency. Present the finding to the user; file it only
after explicit per-finding authorization. Check the target repo's live open-issue list first.

## Report format

- Single-backend / no duplicate primitive: PASS / FAIL (list any extra crypto crates found)
- Zeroizing-crate soundness + coverage: PASS / FAIL
- Constant-time-crate coverage: PASS / FAIL (cross-reference `constant-time-verification.md`
  for any measured confirmation)
- Sys/binding version coherence: PASS / FAIL
- Deprecation/maintenance status: PASS / FAIL
- Feature hygiene: PASS / FAIL
- Findings drafted (not yet filed): list them
