# Key-custody / memory audit

**Applies to:** QuCustody (`breachsafe-custody`). As of this file's last verification,
QuCustody has **no crate code yet** — it's in design phase. That changes what this file is
*for* right now:

- **Today:** apply this file as **design-review guidance against QuCustody's ADRs and
  docs** — read its design claims and ask "does this design commit to a protection claim the
  OS primitives can actually back," using the sourced ground truth below. There is no code
  to grep or run tools against yet; don't force one of the code-level checks (secure-heap
  init call, `unsafe` containment) into a false PASS/FAIL against nonexistent source. Report
  those as N/A — not built — and instead review whether the *design* documents the honest
  version of each guarantee.
- **Once crate code exists:** run the full checklist below as a code audit, including the
  property-harness checks (core-dump scrape, sibling-reader), which are meaningless against
  a design doc.

Also relevant wherever another component in the platform holds a live private key in
memory and signs in place (e.g. QuCert's CA-key handling, `ca-design-anti-patterns.md`
footgun A8 references this file for the deeper version of that check).

**Audit only — draft findings, file nothing without explicit per-finding authorization from
the user (see SKILL.md's authorization gate).**

A key-custody library's entire value is in whether its protection *claims* hold against what
the OS actually guarantees. This file checks claims against sourced reality — the sourcing
below should be treated as "verified as of this file's last check," and re-verified before
being repeated in a real finding, since library GA status and platform capability both move.

## The sourced ground truth

1. **Memory protection is heap-only.** `mlock`/`memfd_secret`/zeroize protect the at-rest
   heap copy; the key is necessarily present in CPU registers, stack spills, and
   intermediate values during actual signing/decryption operations. No software-only tier
   prevents this — only a TEE does. (Consistent with `libsodium` and the `zeroize` crate's
   own documented limits.)
2. **OpenSSL's secure-heap (`CRYPTO_secure_malloc`) is OFF by default** — without an
   explicit `CRYPTO_secure_malloc_init(N, M)` call it behaves as plain `OPENSSL_malloc`
   (i.e., the key is NOT protected, silently). Once initialized, a PQC signing key *does*
   land in it (this should be verified empirically per-target, since the exact allocation
   delta is OpenSSL-version and key-type dependent — don't assume a specific byte count from
   an old audit still holds).
3. **The real at-rest baseline is full-disk encryption + disabled hibernation + encrypted
   or disabled swap.** Memory-locking is secondary defense-in-depth. Hibernation writes all
   of RAM to disk, bypassing `mlock` entirely — this is why `memfd_secret`'s own authors
   recommend disabling hibernation while a secret region is live. Disabling core dumps alone
   is insufficient; it doesn't stop hibernation, swap, or a privileged ptrace attach.
4. **`memfd_secret`'s honest guarantee:** it takes the region off the kernel's direct map
   and resists a kernel buffer-overread bug — it does **not** resist a fully-privileged
   (root) attacker or arbitrary kernel code execution. It must be runtime-probed, not assumed
   present: container default seccomp policies commonly block the syscall (`EPERM` even on a
   kernel that supports it), and some architectures/kernel builds return `ENOSYS`. Treat both
   errno values as "unavailable, fall through" — a probe that only handles one is incomplete.
5. **`mlock` needs `RLIMIT_MEMLOCK`** (a small default limit on many systems) and possibly an
   elevated capability in containers — probe for availability, don't assume it. This is part
   of why several well-known crypto libraries do NOT `mlock` by default; a component that
   goes further than that peer baseline is a deliberate choice and owns the operational cost
   of getting the probe right.
6. **Windows DPAPI is a weak tier.** It's password/credential-bound with a comparatively
   weak KDF, and the protected blob is extractable given the right local privilege. It
   belongs at a weak "OS-wrapped" tier — not anywhere near a hardware-sealed tier.
7. **Non-extractable key-storage tiers — verify current GA status per-platform, since this
   moves fast and has been a source of overclaim before (see the correction below):**
   - **macOS Secure Enclave** — a genuine hardware secure element. Keys generated *in* the
     enclave are non-importable and non-exportable by design. Verify current PQC-algorithm
     GA status on the target macOS version before asserting it's available; treat availability
     as probe-gated (attempt the operation / query the specific algorithm), not
     version-sniffed.
   - **Windows CNG — see the corrected entry immediately below. Do not use an older draft's
     description of this tier; it overclaimed hardware backing.**

### Corrected: Windows ML-DSA key protection is software-KSP + VBS isolation today, not TPM-backed

An earlier version of this audit's ground truth claimed:

> "Windows CNG-TPM-KSP — `NCryptCreatePersistedKey` + `NCryptSetProperty
> (NCRYPT_EXPORT_POLICY_PROPERTY, 0)` = key never leaves the TPM; ML-DSA-44/65/87 are GA
> in CNG/SymCrypt ... TPM provider preferred (`MS_PLATFORM_CRYPTO_PROVIDER`), software-KSP
> fallback probed."

**This overclaims hardware backing and must not be repeated.** The corrected, current-state
fact:

> **Windows ML-DSA key protection today is a software Key Storage Provider (KSP) isolated
> via VBS (Virtualization-Based Security), NOT TPM-hardware-backed.** ML-DSA-44/65/87 are GA
> in CNG/SymCrypt on current Windows releases, but the GA path resolves to Microsoft's
> software KSP with the key isolated inside the VBS/VSM (Virtual Secure Mode) boundary, not
> the physical TPM path (`MS_PLATFORM_CRYPTO_PROVIDER`). `NCryptCreatePersistedKey` +
> `NCryptSetProperty(NCRYPT_EXPORT_POLICY_PROPERTY, 0)` does make the key non-exportable
> through the CNG API — that is a real, meaningful guarantee (it resists a compromised
> normal-mode process reading the key out via the API) — but "non-exportable via the API" is
> a materially weaker claim than "key never leaves the TPM." VBS isolation protects against
> a compromised normal-mode OS/kernel; it does **not** give the physical-secure-element
> guarantee that a discrete TPM or a true hardware enclave gives (e.g. resistance to a
> physical/firmware-level attacker, or to a VBS-bypassing hypervisor compromise). **Do not
> describe this tier as "hardware-sealed" or say the key "never leaves the TPM"** — say
> "non-exportable, VBS-isolated software KSP."
>
> **Future / roadmap, not current:** a genuinely TPM-backed ML-DSA path
> (`MS_PLATFORM_CRYPTO_PROVIDER`) may become available as TPM 2.0 PQC algorithm support
> matures on real hardware. Treat that as a roadmap item to re-verify at audit time — do not
> assert it as today's reality, and flag any design doc or code comment that already asserts
> it as an overclaim finding.

**Tier classification, corrected.** The old tier table placed Windows ML-DSA custody at the
same "HardwareSealed" tier as macOS Secure Enclave. That is no longer correct. Use a ladder
with a distinct middle tier instead:

```
HeapZeroize (floor)
  < OsWrapped / DPAPI-weak (extractable, weak KDF, credential-bound)
    < VbsIsolated / software-KSP  ← current Windows ML-DSA sits HERE
      < HardwareSealed  ← macOS Secure Enclave (true hardware secure element);
                           a future genuine TPM-backed Windows path would also belong here,
                           once and only once it's actually GA — verify before claiming it
```

`VbsIsolated`/software-KSP is real protection — stronger than DPAPI's weak tier, since the
key isn't extractable via the CNG API and VBS raises the bar past a simple compromised-kernel
read — but it is **not** the same guarantee class as a physical secure element, and a design
or code claim that conflates the two is an overclaim finding, not a nit.

## The audit checks

### 1. Secure-heap is actually initialized (the #1 silent-insecure failure)

*Code-level check — N/A until QuCustody has crate code; for a design review, check the ADR
actually commits to this step rather than assuming it.*

- [ ] The custody library calls the secure-heap init function exactly once at startup,
      before any key generation.
- [ ] A self-check confirms secure-heap usage actually grew after key generation — the live
      proof the key landed in protected memory. Without this, "in-use protection" is an
      unverified claim, not a fact.
- [ ] If init fails (insufficient privilege / resource limit), the achieved tier degrades
      and that degradation is reported — never silently claims protection it doesn't have
      (fail-closed).

### 2. Probe, never version-sniff

*Code-level check — N/A until crate code exists; for design review, check the design
commits to runtime probing rather than a version/OS check.*

- [ ] Every OS-tier availability check is a runtime probe (attempt the operation, or a
      documented capability query), never a bare `cfg!(target_os/kernel_version >= X)`.
      Container seccomp policies, architecture-specific `ENOSYS`, and DPAPI-without-a-TPM all
      defeat a version check; only a probe is correct.
- [ ] `memfd_secret` probing (if used) treats both `EPERM` (seccomp-blocked) and `ENOSYS`
      (unsupported kernel/arch) as "unavailable, fall through" — not just one of the two.
- [ ] Non-extractable-tier probing (CNG-KSP / Secure Enclave) probes for the *specific
      algorithm's* support and lights up automatically; it does not assume availability from
      OS version alone.

### 3. Two-axis tier model, not one ladder

- [ ] At-rest protection and in-use protection are modeled as **separate** axes/enums (e.g.
      keychain-vs-mlock is a category error if forced onto one linear ranking) — any
      `--min-*` floor applies per-axis, not to a single combined score.
- [ ] Negotiation returns one backend via composition of the two axes (e.g. a decorator
      pattern wrapping an at-rest base with an in-use layer), and capability *probing* is
      kept separate from actually *constructing* a backend — no throwaway keygen performed
      just to test a tier that ultimately loses.

### 4. Honest claims — labels match reality

- [ ] Every tier's label/doc matches its sourced guarantee exactly — using the corrected
      language above for the Windows tier (`VbsIsolated`/software-KSP, not "HardwareSealed"
      or "TPM"), and the equivalent honest phrasing for every other tier (e.g. `memfd_secret`
      = "off the kernel direct map, not root-proof"; DPAPI = "weak, extractable,
      credential-bound"; the heap-only floor = "in-use-readable — a sibling process reading
      `/proc/pid/mem` can exfiltrate it").
- [ ] An explicit "honest limits" section states the heap-only/registers caveat (fact 1
      above) AND that FDE + disabled hibernation + encrypted swap is the *primary* at-rest
      baseline, with memory-locking tiers as defense-in-depth on top of it — not the other
      way around.
- [ ] No tier is described as "HSM-grade" or "memory-reader-proof" unless it is genuinely a
      TEE or a physical HSM.

### 5. The fail-closed insecure gate

- [ ] Landing on the fully-insecure floor (no at-rest protection + heap-only in-use
      protection) **refuses** to proceed unless an explicit, deliberately-typed
      "allow insecure" flag is set — impossible to hit by accident.
- [ ] Silent downgrade is forbidden: the achieved tier is always surfaced/logged. A
      strict-expectation mode detects "negotiated above the floor but below what the host
      was actually capable of" as its own condition, distinct from "below the floor."
- [ ] The custody error type's variants are typed and non-secret only (operation label,
      tier, errno) — never a `String` built from key-adjacent data. Adversarially test this:
      grep `Display`/`Debug` implementations for any path that could format a byte from the
      key itself.

### 6. Non-extractable export policy is set correctly

- [ ] Windows: `NCRYPT_EXPORT_POLICY_PROPERTY = 0` is set on the persisted key; scope
      (machine vs. user) matches the design's stated model. **Do not require or assume
      `MS_PLATFORM_CRYPTO_PROVIDER` (the TPM provider) as "preferred"** — per the correction
      above, the current GA path is the software KSP under VBS isolation. If code or a doc
      *claims* TPM backing, verify it against an actual runtime provider probe; an unverified
      TPM claim is itself a finding. Release uses `NCryptFreeObject`, not `NCryptDeleteKey`
      (the latter destroys the persisted key rather than just releasing the handle).
- [ ] macOS: the key is generated *inside* the Secure Enclave (not imported as plaintext and
      then wrapped) — verify the actual API call used, since an import-then-wrap flow does
      not give the enclave's real guarantee even if it superficially resembles one.
- [ ] Only genuinely hardware-backed tiers (macOS SE; a verified-current TPM path if one
      exists) are exempt from implementing an "extractable" interface. The Windows
      VBS-isolated software-KSP tier is non-exportable-via-API but should NOT be classified
      alongside true hardware for any claim stronger than that.

### 7. `unsafe` is contained (composes with `unsafe-ffi-verification.md`)

- [ ] All OS syscalls (`mlock`/`memfd_secret`/`NCrypt*`/`SecKey*`) live in one designated FFI
      shim file with a `// SAFETY:` comment per `unsafe` block; platform-gated and
      feature-gated so a non-target build doesn't pull in the platform-specific dependency.
- [ ] Run `unsafe-ffi-verification.md`'s Miri/sanitizer checks against that shim — it's the
      highest-risk code in the library; a marshaling bug here corrupts or leaks the key
      itself, not just a benign buffer.

### 8. Validate the property, not just the function (integration harnesses)

A custody library at this trust level should ship these as CI gates — they test what a unit
test cannot:

- [ ] **Core-dump scrape:** deliberately crash a process holding a key, grep the resulting
      core dump for the key's byte pattern, and confirm it's **absent** for every protected
      tier (a control case — a naive unprotected `Vec` — SHOULD leak, proving the test itself
      is meaningful). Platform-dependent: core dumps are commonly enabled on Linux, off by
      default on macOS.
- [ ] **Sibling-reader:** a second process reads the first process's memory (e.g.
      `/proc/pid/mem` on Linux) and confirms the heap-only floor tier **is** readable (the
      honest baseline) while a protected tier (`memfd_secret`/secure-heap, on a host that
      supports it) is **not**.
- [ ] Their absence means every tier's guarantee is asserted but untested — flag that
      explicitly rather than treating "the code compiles and unit-tests pass" as proof the
      property holds.

## What to do with a finding

**Audit only. Draft, don't file.** Per the authorization gate in `SKILL.md`, draft the
finding — cite the sourced fact it violates, and for the corrected Windows claim
specifically, cite this file's correction rather than an older doc — and present it to the
user. File it only after explicit per-finding authorization. Check the target repo's live
open-issue list first; don't rely on any issue-number list embedded in a skill file.

## Report format

- Secure-heap initialized + self-checked: PASS / FAIL / N-A (no code yet)
- Probe-not-version (including both `memfd_secret` errno cases, DPAPI-without-TPM): PASS /
  FAIL / N-A
- Two-axis model + decorator composition + probe-separate-from-construct: PASS / FAIL / N-A
- Honest labels + honest-limits section + FDE/hibernation stated as the primary baseline:
  PASS / FAIL — **explicitly confirm the Windows tier is labeled `VbsIsolated`/software-KSP,
  not `HardwareSealed`/"TPM"**
- Fail-closed insecure gate + no key material in error types: PASS / FAIL / N-A
- Non-extractable export policy set correctly (Windows VBS-isolated tier language correct;
  macOS SE generated-in-enclave): PASS / FAIL / N-A
- `unsafe` contained (+ ran `unsafe-ffi-verification.md`): PASS / FAIL / N-A
- Property harnesses (core-scrape, sibling-reader): PRESENT / ABSENT / N-A
- Findings drafted (not yet filed): list them
