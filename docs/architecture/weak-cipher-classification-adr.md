# ADR: Weak cipher classification and detection

**Status:** Proposed

## Contents

1. [Context](#1-context)
2. [Sources of truth, vendored and cited](#2-sources-of-truth-vendored-and-cited)
3. [The classification policy](#3-the-classification-policy)
4. [Detection: the ClientHello probe](#4-detection-the-clienthello-probe)
5. [One registry, every reader rates from it](#5-one-registry-every-reader-rates-from-it)
6. [Consequences](#6-consequences)
7. [References](#7-references)

## 1. Context

QuReddy's OpenSSL probe asks whether a target negotiates the one strongest suite. It does not
enumerate the weak suites a target still offers, so a server exposing TLS 1.0/1.1 or a
SWEET32-vulnerable 3DES cipher can read `hygiene=ok` (issue #672). Two audit findings compound
this: the summary and the CBOM disagree about a detected weak cipher (#705), and suites the
pinned OpenSSL 3.5.7 build compiles out are silently absent from the report, carrying no not-testable marker (#706).

This ADR defines how QuReddy classifies a cipher suite as weak and how it detects one on the
wire. It is the policy behind the native probe (#700), the rating registry (#708), and the
vendored weak-set import (#709), under milestone 0.16.0 (master #591).

## 2. Sources of truth, vendored and cited

A weak verdict records the source that assigns it. QuReddy never enumerates the weak set from
memory. The IKE side already learned this: a finding once cited "RFC 8247 classifies IKEv1 as
Historic," which that RFC never says (the status is RFC 9395). The same discipline applies here.

Vendor these, each with its release, `updated` date, and digest, the way `standards/rfc/iana-ike/`
is vendored:

| Source | Assigns |
|---|---|
| IANA TLS Cipher Suite registry (structure per RFC 9847) | the `Recommended` column: `Y`, `N`, `D` |
| RFC 9325, BCP 195 (obsoletes RFC 7525) | forward-secrecy requirement and the MUST-NOT suites in section 4.2 |
| RFC 8996 | TLS 1.0 and TLS 1.1 deprecated |
| RFC 9155 | MD5 and SHA-1 signature hashes deprecated in TLS 1.2 |
| RFC 5469 | DES and IDEA cipher suites deprecated |
| RFC 7465 | RC4 prohibited |

A rating that cannot cite one of these sources is a bug.

## 3. The classification policy

RFC 9847 (2025) is the change that makes this precise. It expanded the IANA `Recommended` column
beyond `Y`/`N` and added `D`. The three values do not mean what a reader assumes:

| `Recommended` | Meaning | QuReddy verdict |
|---|---|---|
| `Y` | IETF-endorsed at registration | not weak on this axis |
| `N` | no IETF consensus. The IETF takes no position | **not a weakness verdict.** Do NOT flag `N` as weak |
| `D` | Discouraged, an explicit signal added by RFC 9847 | weak: report it |

The trap to avoid: treating `N` as "weak." Most `N` suites simply never went through IETF
consensus and can be cryptographically sound. Only `D`, plus the RFC-deprecated set, are a
weakness verdict:

- **RFC-deprecated (definitively weak):** EXPORT, anonymous (no authentication), RC4, DES, IDEA,
  MD5 and SHA-1 signature hashes, and the TLS 1.0/1.1 protocol versions.
- **`D` in the registry:** actively discouraged by IETF consensus.

Two independent axes, never merged (issue #616, mirroring the IKE rule):

- **Classical weakness:** the suite is broken or weakened today (3DES/SWEET32, RC4, DES, NULL,
  EXPORT, MD5). Record the specific defect. SWEET32 is a 64-bit **block** weakness, distinct from
  key bits: 3DES has 112-bit key strength yet is SWEET32-exposed, so `block_bits` is a separate
  field from `classical_bits`.
- **Quantum vulnerability:** the key exchange is classical, hybrid, or pure post-quantum. A
  classically-sound suite can still be quantum-vulnerable at key establishment, and saying so
  precisely is the product's value.

## 4. Detection: the ClientHello probe

Detection does not require OpenSSL to support the cipher. QuReddy offers the suite's two-byte
IANA id in a ClientHello and reads which suite the server selects. Selection is not negotiation:
the probe stops after the ServerHello, so it needs no key exchange and no crypto library support
for the offered suite. This is the native ServerHello selector of #700.

```
for suite_id in weak_set (from the vendored registry):
    send ClientHello{ cipher_suites: [suite_id, ...] }   # raw bytes; batched to bound round-trips
    read the first response record:
        ServerHello selected in offered   -> OFFERED     -> finding, rated from the registry
        handshake_failure / alert / none  -> NOT_OFFERED
        selected outside the offered set  -> AMBIGUOUS    -> never accepted as evidence
    stop after ServerHello
```

A suite the local build cannot enumerate is reported `NOT_TESTABLE`, never silently omitted
(#706). The existing timeout path already models this honest state.

## 5. One registry, every reader rates from it

The classification and the detection share a single canonical cipher-suite registry (#708):

```
weak_ciphers.json  (one vendored, digest-pinned file, many consumers):
  meta:   { source (IANA registry + RFC clause), updated, sha256 }
  suites: [ { id (IANA), name, recommended (Y|N|D), weak (bool),
              classical_bits, block_bits, kex_axis (classical|hybrid|pure_pq) } ]
```

Facts only. No control ids, no framework versions, no OSCAL. The mapping from a verdict to a
control lives in the OSCAL lane described below.

The probe reads `suite_id` to know what to offer. The classifier, CBOM, and CISO summary read the
same ratings, so they cannot disagree (this closes the #705 drift by construction).

**Facts and verdict are separated, the way a CBOM separates them.** The probe emits what it
observed on the wire as fact (OFFERED, NOT_OFFERED, NOT_TESTABLE, AMBIGUOUS) and rates nothing.
The weak verdict lives in the registry, vendored from IANA and the RFCs with its release,
`updated` date, and digest, so a new suite enters the weak set by re-vendoring that file while the
scanner code stays fixed. This mirrors IBM's CBOM tooling, where detection records the
cryptographic asset and a separate versioned compliance policy decides whether it is quantum-safe
or weak. The registry file is that policy for QuReddy: a vendored, digest-pinned JSON file read at load
time. Only the loader and the row type are Python; the ratings themselves stay in the file.

**Control-framework mapping reuses the SCF QTS OSCAL catalog; it is not built into this file.**
The cipher registry holds crypto facts. Mapping a verdict to a control is a separate concern that
already exists in the OSCAL lane: mint-oscal carries a readiness crosswalk onto the SCF 2026.2 QTS
catalog, keyed by crypto property (`quantum_vulnerable -> qts-04.3`, `classically_weak -> qts-06.5`,
`transitional_hybrid -> qts-06.9`, `quantum_ready -> qts-06.3`). QuReddy emits CBOM from this
registry; the OSCAL lane consumes that CBOM, selects the PQC-pack profile, and with a customer
scope mints an OSCAL Assessment Plan and Results, where an unobserved control is NOT_ASSESSED. SCF
owns the QTS controls, attributed to SCF's namespace with control text unchanged; BreachSAFE owns
the crosswalk and profile, stamped provisional until the mapping is reviewed. Frameworks that move
on their own cadence (NIST SP 800-53, PCI DSS) attach as further crosswalk entries in the OSCAL
registry, so a framework revision never touches this file. This mapping path is out of scope for
the native probe (#700) and the first registry import (#708); it is recorded here to fix the
boundary: crypto facts in `weak_ciphers.json`, control mapping in the OSCAL lane.

## 6. Consequences

- QuReddy can report a server that offers only a weak suite, including one OpenSSL 3.5.7 compiles
  out, closing the #672 blind spot.
- The summary, CBOM, and hygiene axes agree, because they rate from one table (#705).
- Coverage is honest: OFFERED, NOT_OFFERED, NOT_TESTABLE, or AMBIGUOUS, never a silent omission
  (#706).
- `N` suites are not mislabelled weak, so QuReddy does not over-report where the IETF took no
  position.
- The weak set tracks IANA and the RFCs by re-vendoring the registry; source literals are
  never edited to add a suite.

## 7. References

- IANA TLS Parameters, TLS Cipher Suite registry.
- RFC 9847, IANA Registry Updates for TLS and DTLS (the `Y`/`N`/`D` structure).
- RFC 9325 / BCP 195, Recommendations for Secure Use of TLS and DTLS (obsoletes RFC 7525).
- RFC 8996 (TLS 1.0/1.1), RFC 9155 (MD5/SHA-1), RFC 5469 (DES/IDEA), RFC 7465 (RC4).
- RFC 10015, obsolete TLS 1.2 key-exchange classifications (issue #701).
- QuReddy issues: #672, #700, #701, #705, #706, #708, #709, #616. Milestone 0.16.0, master #591.
