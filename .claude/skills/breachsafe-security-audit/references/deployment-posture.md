# Deployment posture (TEE / FIPS-140 module mode / key custody at the server layer)

**Applies to:** whichever BQP component runs as a network-facing service holding or using
live keys at runtime (e.g. a future KMS/server layer sitting on top of QuCrypt/QuCert). As of
this file's last verification, that server layer does not exist yet in any BQP repo — **every
section below is currently N/A, gated, per the pattern this file itself enforces.** Re-check
whether it now exists before running this file's checks; don't assume the gate is still shut
just because it was the last time this ran.

**Audit only — draft findings, file nothing without explicit per-finding authorization from
the user (see SKILL.md's authorization gate).**

This file audits how a server-layer component protects keys at **runtime**: keys-in-use
(confidential computing / TEE), the validated-module boundary (FIPS 140-3), and where keys
physically live (custody backend). It's the deployment counterpart to the correctness checks
in `crypto-correctness-checklist.md` and to `breachsafe-conformance`'s standards work.

## Gate first — do not test vapor, do not claim a false pass

Run this before any section below. Audit only what exists.

```bash
# Run from the repo root of whichever component might have a server crate.
test -d <server-crate-path> && echo "server surface present" || echo "GATE: no server crate — Sections 1-3 N/A"
grep -rl 'fips' <crates-glob>/Cargo.toml <crates-glob>/src 2>/dev/null || echo "GATE: no fips build/feature — Section 2 N/A"
<openssl-or-equivalent-cli> list -providers 2>/dev/null | grep -i fips || echo "GATE: no FIPS provider on this host — Section 2 not runnable here even if the feature exists"
```

If a section's prerequisite is absent, record **"surface not built — N/A"** for that
section. **Never report "PASS / no issues" for a posture that has no implementation yet** —
that is a false assurance. "Not built" is not the same claim as "secure," and reporting it
as a pass actively misleads whoever reads the audit later.

## Section 1 — confidential computing / TEE (gate: a server surface exists)

A server that decrypts private keys into RAM on every operation needs this section to verify
keys-in-use are protected from the host/hypervisor, and that callers can attest the server
before trusting it with a key.

- [ ] **Process model:** does the server run inside a TEE (a hardware-isolated
      enclave/confidential-VM technology)? Check deploy manifests / Dockerfile / IaC for
      enclave configuration. Plain VM/container with no such isolation → finding (keys are
      readable via host/hypervisor memory access).
- [ ] **Remote attestation:** is there an endpoint returning an attestation document (an
      enclave measurement or equivalent) so a caller can verify the server's identity and
      code measurement before trusting it with a key operation? Absent → finding.
- [ ] **Key sealing:** are at-rest keys sealed to the TEE's measurement (only that exact
      enclave build can unseal them), or are they decryptable outside the enclave?
- [ ] **Memory hygiene extends into the server layer:** the zeroize discipline checked in
      `crypto-correctness-checklist.md` for the core library must also hold at the server
      layer — a TEE doesn't excuse leaving key bytes in RAM longer than the operation needs.
- [ ] **No debug/SSH access into the enclave** in production configuration; the enclave
      image is reproducible so the attested measurement can actually be independently
      verified by a caller.

```bash
grep -rniE 'nitro|enclave|tdx|sev|snp|attestation|vsock' <server-crate-path>/ deploy/ 2>/dev/null
```

## Section 2 — FIPS 140-3 module mode (gate: a FIPS build/feature AND a FIPS provider are
both present)

Distinct from FIPS *algorithm* conformance (owned by `breachsafe-conformance`'s known-answer
testing). This section is about the **validated module boundary** — a different, stricter
claim.

- [ ] Which crypto provider is actually loaded at runtime — the default provider, or an
      explicitly FIPS-validated one? (The default provider being algorithm-correct does NOT
      make it FIPS-140 compliant — module validation is a separate certification from
      algorithm correctness.)
- [ ] If a "fips" build/feature exists, does it actually load the FIPS provider and **fail
      closed** (refuse to start, not silently fall back) if that provider is unavailable?
- [ ] **Which specific PQC algorithms are actually inside the validated boundary** — FIPS
      module validation for ML-KEM/ML-DSA in a given crypto library's provider is an evolving
      area; verify per-algorithm rather than assuming the whole library is covered by one
      validation.
- [ ] **No overclaim:** any doc/README/marketing text claiming "FIPS 140-3 compliant" must
      match exactly what the loaded provider is actually validated for. A false FIPS-140
      claim is a compliance liability, not a documentation nit — treat it as a high-severity
      honesty finding.

```bash
<openssl-or-equivalent-cli> list -providers | grep -iA2 fips
grep -rniE 'fips.140|fips.compliant|validated.module' <crates-glob>/ *.md docs/ 2>/dev/null
```

## Section 3 — key custody backend at the server layer (gate: a custody backend is actually
implemented)

Audit whatever custody backend the server component actually ships — not what a design doc
proposes for it eventually.

- [ ] **Tier:** software store (e.g. a plain database/in-memory map) / cloud KMS / HSM via
      PKCS#11? Identify which is actually wired up.
- [ ] **Raw-key exposure:** is the raw private key ever in application-readable memory or
      in a database in cleartext? For a software store, the answer is yes by construction —
      flag this against any "keys never leave the server" or similar claim, since that claim
      is only as strong as the custody tier **combined with** the TEE posture from Section 1,
      not either alone.
- [ ] **If cloud KMS / HSM:** does the backend actually support the PQC key types in use, or
      does it silently fall back to wrapping raw key bytes (which negates most of the
      HSM/KMS benefit)?
- [ ] **Key lifecycle:** is rotation, deletion, and per-key access control actually
      implemented, or is it keygen-and-store only?
- [ ] **The custody tier is behind an abstraction/trait**, so it can be upgraded later
      without re-architecting the server. A hard-coded single-backend implementation with no
      seam is a finding if a stronger tier is a stated future goal — cross-reference
      `custody-memory-audit.md` for the deeper per-tier guarantee checks once QuCustody
      itself has code.

```bash
grep -rniE 'pkcs.?11|cryptoki|kms|hsm|sqlx|hashmap.*key|key_store|keystore' <server-crate-path>/ 2>/dev/null
```

## Section 4 — cross-cutting

- [ ] Mutual TLS (or whatever the platform's stated required transport security is) is
      actually enforced, not optionally configurable with a plaintext fallback.
- [ ] Request/response bodies are never logged where they could contain key material or
      sensitive ciphertext/key-identifier pairs — grep for body-logging middleware.
- [ ] **The three postures compound — report the combined weakness, not three isolated
      checkboxes.** A software custody store (Section 3) *without* a TEE (Section 1) means
      raw key bytes sit in host-readable RAM even if each section individually only got a
      "partial" rating; call out the combined trust boundary explicitly in the report.

## What to do with a finding

**Audit only. Draft, don't file.** State the surface (TEE / FIPS mode / custody / transport),
the gap with the exact command output proving it, why it matters (the concrete runtime
attack — a host memory dump reading keys, a non-validated provider being marketed as
validated, etc.), and cross-reference the design doc/ADR governing that surface if one
exists. Present it to the user; file it only after explicit per-finding authorization. Check
the target repo's live open-issue list first, and prefer commenting on an existing tracking
issue for that surface over opening a duplicate.

## Honesty rules

- "Surface not built" is the correct verdict for an unimplemented posture — never "pass."
- A TEE/HSM/FIPS-mode claim is "present" only when independently verified running (provider
  actually loaded, an attestation document actually returned, a PKCS#11 module actually
  linked) — not because a config file or doc merely mentions it.
- Posture weaknesses compound. Report the combined trust boundary (custody × TEE × FIPS),
  not three isolated PASS/FAIL lines that individually look better than the real picture.
- A "FIPS-140 compliant" or "keys never leave the server" claim the implementation doesn't
  actually back is a high-severity honesty finding, not a nit.
