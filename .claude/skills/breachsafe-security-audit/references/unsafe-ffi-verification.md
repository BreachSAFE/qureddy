# Unsafe-FFI / undefined-behavior verification

**Applies to:** QuCrypt and QuCert (Rust components) — specifically whatever module each
repo designates as its sole permitted `unsafe` FFI boundary. Not applicable to QuReddy/Qurum
(Python).

**Audit only — draft findings, file nothing without explicit per-finding authorization from
the user (see SKILL.md's authorization gate).**

`crypto-correctness-checklist.md`'s stop-the-line list greps for `unsafe` appearing outside
the designated FFI shim — a real and useful check, but it only verifies *placement*. It
cannot verify the `unsafe` blocks **inside** that shim are actually sound. Those blocks
typically call a C KEM/signature API directly with in/out length pointers and raw buffer
pointers — exactly the shape where undefined behavior hides: aliasing, reading uninitialized
output, writing past a buffer, or an in/out length-contract violation the Rust type system
cannot catch. This file **measures** soundness with Miri and sanitizers rather than reading
the code and hoping.

**Locate the actual FFI shim before starting — its path has moved before within this
codebase family** (e.g. from a flat `src/kem_ffi.rs` to a per-primitive `src/kem/ffi.rs` as
the crate was restructured). Check the crate's own module wiring (`lib.rs`) and its
architecture doc rather than assuming a path from memory or an older doc.

## Reality check first — Miri cannot execute a linked C FFI call

Miri interprets Rust MIR; it does not run linked C code. You cannot `miri test` a real
encapsulate/decapsulate (or equivalent) round-trip end-to-end — it errors at the `extern "C"`
call boundary. Miri's value here is on the **Rust-side glue**: buffer construction,
slice/pointer handling, pointer provenance, length-variable setup, and the lifetime of any
zeroizing/owned buffer around the FFI call. Use it against a harness that exercises that glue
(ideally with the FFI symbol mocked), and rely on a sanitizer build for the actual C-side
boundary.

**Be honest about this split in the report.** Claiming "Miri verified the FFI call" when
Miri actually aborted at the C boundary and only the Rust-side setup ran is the exact kind of
overclaim this file exists to prevent.

## Setup — validate the toolchain before running, don't skip this

```bash
# Run from the crate root.
rustup toolchain list | grep -q nightly || rustup toolchain install nightly
rustup +nightly component add miri
```

If nightly/Miri can't be installed on this machine, **stop and say so** — draft an
infrastructure finding requesting Miri in CI. Do not report "no UB found" when the tool never
actually ran.

## Step 1 — read the unsafe blocks and their SAFETY contracts

```bash
grep -n 'unsafe\|SAFETY\|as_mut_ptr\|as_ptr' <path/to/the/ffi/shim>
```

For each `unsafe { ... }` block calling into the C API, confirm the `// SAFETY:` comment's
claims actually hold against the underlying library's documented contract (its man page or
equivalent reference):

- in/out length variables are initialized to actual buffer capacity before the call,
- output buffers are sized to the standard-mandated constant (verify the size against
  `crypto-correctness-checklist.md`'s table, not memory) before the call,
- length variables are re-checked **after** the call against the expected constant,
- the underlying context object is freshly created per operation, never reused across calls,
- the raw pointers passed in come from live, owned allocations (`Vec`/the crate's zeroizing
  type) that outlive the call.

A `SAFETY` comment that asserts something the underlying library's contract does not actually
guarantee is a finding even if no test currently fails because of it — it's a latent bug
waiting for an input shape that exercises it.

## Step 2 — Miri on the Rust-side glue

```bash
MIRIFLAGS="-Zmiri-strict-provenance" \
  cargo +nightly miri test --lib <module-that-exercises-buffer-setup-before-the-FFI-hop> \
  2>&1 | tail -30
```

Scope Miri to tests that exercise size guards and slice handling *before* the FFI hop —
tests that actually cross into the linked C code will abort at that boundary; that's
expected, not a failure of Miri itself. Read the output for: `Undefined Behavior`, `using
uninitialized data`, `out-of-bounds`, `dangling pointer`, `not granting access`. Any such
line → Step 4, draft a finding.

If Miri aborts at the `extern "C"` boundary for every test that reaches the real primitive
(likely, since the real functions call into linked C code), record that Miri's coverage of
the FFI path itself is **zero** and rely on Step 3 for that side. Report this gap honestly
rather than letting it read as "Miri covered it."

## Step 3 — sanitizer build for the real C boundary

AddressSanitizer *does* cross into linked C code, so it can catch out-of-bounds or
use-after-free on the actual encapsulate/decapsulate (or equivalent) buffers.

```bash
RUSTFLAGS="-Zsanitizer=address" \
  cargo +nightly test --target <your-target-triple> <the-ffi-round-trip-test-name> \
  2>&1 | tail -40
```

Read for ASan reports: `heap-buffer-overflow`, `stack-use-after-return`, `use-after-free`,
`SEGV`. Each is a security finding with the exact buffer and call site named.

If the sanitizer build fails for toolchain/target reasons unrelated to a real bug, record
"sanitizer build unavailable on this host" rather than claiming a clean result — an
unavailable tool is not evidence of soundness.

## Step 4 — what to do with a finding

**Audit only. Draft, don't file.** State the tool (Miri or the sanitizer), the exact
location (file:line, function), the raw tool output, why the grep-based checks in
`crypto-correctness-checklist.md` couldn't have caught this class of bug, and the exact
reproduction command. Present it to the user; file it only after explicit per-finding
authorization. Check the target repo's live open-issue list first.

## Report — state coverage honestly

- Nightly/Miri available: yes/no
- Miri over the Rust-side glue: PASS / UB found / NOT RUN (aborted at the C boundary)
- Sanitizer over the real FFI round-trip: PASS / finding / build unavailable
- **Explicitly state what was NOT covered** — e.g. "Miri did not execute the linked C call;
  only the Rust-side buffer setup was checked" is a required sentence in the report whenever
  it's true, not an optional caveat.

## Honesty rules

- Never report "the FFI shim is verified, no UB" if Miri aborted at the C boundary and the
  sanitizer build didn't run. Partial coverage must be labeled partial, every time.
- A clean Miri run on size-guard tests does not cover the actual C-boundary call. Say so
  explicitly in the report rather than letting a reader infer full coverage.
