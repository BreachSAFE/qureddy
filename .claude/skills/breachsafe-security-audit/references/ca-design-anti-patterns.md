# CA-design anti-patterns (RFC-mapped, precedent-grounded)

**Applies to:** QuCert (`breachsafe-pki-rs`) — its primary reason to exist is not replicating
these exact bugs. Not applicable to QuCrypt (no CA logic) or QuCustody (no code yet); revisit
for QuCustody once it handles CA-adjacent key material directly.

**Audit only — draft one finding per footgun found (quote the RFC line + name the
precedent), file nothing without explicit per-finding authorization from the user (see
SKILL.md's authorization gate).**

Structural X.509 conformance (does the cert parse correctly, right OIDs, right criticality)
is `breachsafe-conformance`'s job. Rust idiom is `breachsafe-quality-review`'s job. **This
file is the third class: CA-design footguns** — security mistakes an *authority* makes that
produce a structurally-valid-but-dangerous certificate, or an exploitable issuance flow.
These are documented, real bugs in reference CA/cert-generation implementations (rcgen,
step-ca) — a PQC CA's whole reason to exist is to not replicate them. If the target repo has
an ADR studying these reference implementations against the RFCs, read it before this file —
it's the source these footguns are drawn from, and it will have the current precedent
citations if they've been revised.

## How to hunt

```bash
# Run from the crate root.
grep -rn 'keyCertSign\|key_cert_sign\|is_ca\|pathlen' src/        # A1/A2/A9
grep -rn 'from_pem\|from_der\|to_pem\|to_der' src/cert            # A15 symmetry (adjust path to actual layout)
grep -rniE 'trusted|cacerts|publicly.?trusted' src/ docs/ README.md  # A11
grep -rnE 'unwrap|expect|panic|format!.*key|to_vec|clone' src/ | grep -i key  # A8
grep -rnE '&str' src/ | grep -iE 'alg|hash'                       # A14
grep -rn 'is_control\|202E\|200B\|2066\|spoof' src/name src/extensions  # A13 (adjust paths)
```

Then **adversarially mint/verify the footgun input and confirm it's actually refused**. A
footgun is "present" only when you reproduce the dangerous output (e.g. actually construct a
non-CA issuer and confirm `mint_ca_signed_leaf`/equivalent returns `Err`; actually construct
an RSA subject key against a PQC-only policy and confirm rejection), not when the code merely
*looks* like it should refuse. A plausible-looking guard that hasn't been exercised is not a
verified finding of "safe" or "unsafe" — it's untested.

## The CA footgun table

Each row: the footgun, the RFC clause it maps to (verify the exact line against the repo's
own vendored RFC text before quoting it — text can be re-vendored at a different revision),
the reference-implementation precedent it must not replicate, and the gate that has to exist
to prevent it.

| # | Footgun | RFC §, verify against local text | Reference-implementation precedent | The gate that must exist |
|---|---------|--------------------------------------|-------------------------------------|--------------------------|
| A1 | **keyCertSign without cA** (privilege escalation — a leaf cert can mint further certs) | RFC 5280 §4.2.1.3 (KeyUsage: "If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension MUST also be asserted") | A generic cert-generation library that lets you build a leaf with `keyCertSign` set and no CA flag | The builder REJECTS `keyCertSign` + ¬`cA`, in the **shared** build path used by both self-signed-mint and CA-issue — not just one entry point |
| A2 | **pathLen without cA+keyCertSign** | RFC 5280 §4.2.1.9 ("CAs MUST NOT include the pathLenConstraint field unless the cA boolean is asserted and the key usage extension asserts the keyCertSign bit") | Generators that emit a `pathLenConstraint` that means nothing without the paired flags | Builder rejects `pathLen` unless `cA && keyCertSign` both hold |
| A3 | **CSR-supplied extensions trusted verbatim** | RFC 2986 §4 — a CSR is a *request*, not an authorization | A CA implementation that treats CSR-embedded extensions (cA, keyUsage, validity, serial, issuer) as trusted input | `sign_csr`/equivalent NEVER copies `cA`/`keyCertSign`/validity/serial/issuer straight from the CSR; CA policy decides every one of those; SANs are validated against provisioner policy, not copied blind |
| A4 | **Missing proof-of-possession** | RFC 2986 §4 — the CSR is "signed using the subject entity's private key" (verify exact wording against local vendored text) | Skipping PoP lets an attacker request a cert binding someone else's public key to their own identity claim | CSR self-signature is verified **before** issuance; issuance refuses on verification failure |
| A5 | **Issuer not validated on the issue path** | RFC 5280 §4.2.1.9 / §6.1.3 | — | The mint/issue function asserts the issuer cert has `cA=TRUE` + `keyCertSign`, is currently within its validity window, AND that the issuer signing key actually matches the issuer certificate's SPKI |
| A6 | **Subject key not algorithm-validated** (a PQC CA silently issues a classical leaf) | RFC 9881 §2/§4 (ML-DSA in X.509) | — | Caller-supplied subject SPKI must be a supported PQC key (right OID + right raw key size) when the platform's stated policy is PQC-only generate |
| A7 | **Weak/predictable serial** | RFC 5280 §4.1.2.2 (positive integer, unique per issuer, callers/consumers must handle up to 20 octets, CAs MUST NOT exceed 20 octets) | Counters or timestamps used as serials | CSPRNG-sourced, ≥64-bit entropy, positive, ≤20 octets; caller-supplied serials are validated against the same rule, never accepted as a plain counter or timestamp |
| A8 | **CA key exposed in plain memory / errors / extractable form** | Secret-hygiene doctrine, not a specific RFC clause | Keys left in heap without scrubbing, in logs, in panics | Key material uses the crate's zeroizing secret type; never appears in an error/`Debug`/panic/log path; if the platform has a secure-heap init step, confirm it actually ran — see `custody-memory-audit.md` for the deeper version of this check |
| A9 | **Path-length not enforced on VERIFY** | RFC 5280 §6 (path validation) | Reference implementations frequently implement §6 only partially or not at all — verify against the current state of whichever library the platform studied, don't assume it's still unimplemented there | `verify_chain`/equivalent enforces `pathLenConstraint` and rejects chains deeper than allowed |
| A10 | **Non-CA accepted as a trust anchor / blind issuer trust** | RFC 5280 §6.1 | A verifier that trusts whatever cert is handed to it as the anchor without checking it's actually a CA cert | `verify_chain`/`verify_self_signed` rejects a `cA=FALSE` cert used as the trust anchor |
| A11 | **Trust overclaim** (honesty, not an RFC clause) | — | — | No code or doc claims a minted cert is "trusted" or "in the OS/browser trust store" — this is a private-trust CA; the claim must never imply public trust |
| A12 | **Validity-window footguns** | RFC 5280 §4.1.2.5 (encoding rule: dates before 2050 use UTCTime, 2050+ use GeneralizedTime) | Unbounded or inverted validity windows | `notBefore < notAfter` enforced; correct time-encoding switchover honored; a sane maximum validity is enforced; `verify_chain` checks the window at verification time too, not just at mint time |
| A13 | **Identity spoofing via control/bidi/invisible characters** | RFC 5280 §4.1.2.4/.6 + Unicode bidi/invisible-character classes (UTS#39) | A documented class of CA bugs where a DN or SAN containing control characters, bidi-override characters, or zero-width characters is accepted and later renders misleadingly | DN **and** SAN construction reject control characters and the bidi-override / invisible-character code-point ranges — verify the current exact ranges against a current Unicode security reference rather than trusting a hardcoded list carried over from an old draft |
| A14 | **Algorithm downgrade via string-typed algorithm parameter** | Platform-internal API-design rule, not an RFC clause | Libraries that accept an algorithm name as a string, allowing a caller to silently request a weaker one | No `&str` algorithm parameter anywhere in the mint/sign/verify surface; `generate` is PQC-only per the platform's stated policy; `verify` dispatches on the algorithm/OID actually embedded in the certificate being verified, never on a caller-supplied string |
| A15 | **Asymmetric API** (`to_*` exists with no public matching `from_*`) | Consume-side completeness, not an RFC clause | Mint-only libraries that never round-trip their own output | `Certificate::from_pem`/`from_der` (or equivalent) is public and actually round-trips a minted cert; verification is exercised on a *parsed* cert (a fresh deserialization), not only on the in-process object still holding constructor state |
| A16 | **God-object CA** | Architectural — check the platform's own design-seam ADRs | A monolithic `Authority`-style struct owning custody, storage, and policy as concrete fields (a documented anti-pattern in at least one widely used reference CA implementation) | Custody/storage/policy are behind traits (seams), not concrete fields; file/function size limits (check the repo's own stated limits) are respected — small single-purpose files are the intended style here, not a smell to fix later |
| A17 | **Missing RFC citation at the enforcement site** | Traceability, not itself an RFC clause | — | Each security-relevant guard (`return Err(...)`) cites the exact RFC/section it enforces, in a comment, and that citation is factually correct against the repo's own vendored spec text — an audit that finds a *wrong* citation should flag it as its own finding, since a wrong citation is worse than no citation |

## File findings

One finding per footgun instance. Suggested categories: `security` (A1–A10, A13, A14 —
privilege/key/downgrade/spoof classes), `rfc-conformance` (A2/A9/A12 — structural), `docs`
(A11 — overclaim), `enhancement`/`cleanup` (A15/A16). Every finding should:

1. Quote the exact RFC line (verified against the repo's own vendored text at audit time).
2. Name the reference-implementation precedent it maps to.
3. Include a reproduction — the adversarial mint/verify that actually demonstrates the
   footgun exists, not just a code-shape match.

**Draft only; do not run `gh issue create` (or equivalent) until the user explicitly
authorizes filing that specific finding — see SKILL.md's authorization gate.** Check the
target repo's live open-issue list first so you don't duplicate a finding someone already
filed; don't rely on any issue-number list carried in a skill file, since that goes stale the
moment the tracker changes.

## Report format

- A1–A2 (keyCertSign/pathLen gates, shared builder path): PASS/FAIL + line
- A3–A6 (CSR/issuer/subject-key trust on the issue path): PASS/FAIL + line
- A7–A8 (serial entropy, CA-key hygiene): PASS/FAIL
- A9–A10 (verify-side §6 pathLen enforcement, non-CA-anchor rejection): PASS/FAIL + line
- A11–A12 (trust-claim honesty, validity-window correctness): PASS/FAIL
- A13–A14 (identity spoofing, algorithm downgrade): PASS/FAIL
- A15–A17 (round-trip symmetry, god-object design, citation accuracy): PASS/FAIL
- Findings drafted (RFC line + precedent + repro, not yet filed): list them
