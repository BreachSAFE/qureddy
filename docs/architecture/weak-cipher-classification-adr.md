<!--
SPDX-FileCopyrightText: 2026 BreachSAFE
SPDX-License-Identifier: Apache-2.0
-->

# ADR: Separate crypto facts, probe plans, and grading policy

**Status:** Proposed

## Contents

1. [Context](#1-context)
2. [Requirements](#2-requirements)
3. [Decision](#3-decision)
4. [Authoritative sources](#4-authoritative-sources)
5. [Classification policy](#5-classification-policy)
6. [Detection and probe profiles](#6-detection-and-probe-profiles)
7. [Alternatives considered](#7-alternatives-considered)
8. [Registry and policy ownership](#8-registry-and-policy-ownership)
9. [Grading and index alignment](#9-grading-and-index-alignment)
10. [Consequences](#10-consequences)
11. [Revisit when](#11-revisit-when)
12. [References](#12-references)

## 1. Context

QuReddy's OpenSSL probe asks whether a target negotiates the strongest offered suite. It does not
fully enumerate weak suites that a target still accepts. A server exposing TLS 1.0, TLS 1.1, or a
SWEET32-vulnerable 3DES suite can therefore report `hygiene=ok` (#672).

Two related gaps increase the impact. The summary and CBOM can disagree about a detected weak
cipher (#705), and suites compiled out of pinned OpenSSL 3.5.7 are absent without a user-visible
coverage state (#706).

This ADR defines the source, classification, acquisition, output, and grading boundaries behind the
native selector (#700), registry (#708), source import (#709), probe plans (#599), and score (#669).

## 2. Requirements

The design must:

1. detect reviewed weak suites that pinned OpenSSL cannot offer;
2. distinguish a wire observation from its sourced rating;
3. use one fact and rating source for Rich, JSON, JSONL, and CBOM;
4. preserve exact registry and probe-plan provenance;
5. represent incomplete acquisition explicitly;
6. support direct TLS and future TLS-ready transports without copying TLS policy;
7. keep framework mappings and OSCAL out of the QuReddy runtime;
8. support protocol-neutral grading after canonical assessments exist;
9. remain bounded and deterministic; and
10. add no Nmap, EOL OpenSSL, or external legacy-scanner runtime dependency.

## 3. Decision

QuReddy will use a compact CBOM-aligned crypto registry for facts and ratings, separate versioned
probe plans for acquisition, and a separate versioned grading policy over canonical capability
assessments. Mint-oscal will own framework mappings and OSCAL construction.

## 4. Authoritative sources

A rating records the source that assigns it. QuReddy does not enumerate a weak set from memory.
Vendor each enabled source with its URI, release or update date, digest, license, and exact row or
clause.

| Source | Purpose |
|---|---|
| IANA TLS Cipher Suites registry | Wire identity, DTLS status, and `Recommended` value |
| RFC 9847 | Current `Y`, `N`, and `D` recommendation semantics |
| RFC 9325 / BCP 195 | Current TLS deployment recommendations |
| RFC 8996 | TLS 1.0 and TLS 1.1 deprecation |
| RFC 9155 | MD5 and SHA-1 signature-hash deprecation in TLS 1.2 |
| RFC 5469 | DES and IDEA suite deprecation |
| RFC 7465 | RC4 prohibition |
| RFC 10015 | Obsolete TLS 1.2 key-establishment methods |
| NIST IR 8547 initial public draft | Quantum-vulnerable key-establishment and signature schemes |
| CycloneDX 1.7 JSON Schema | CBOM crypto-property names and enums |

An individual Internet-Draft, including `draft-dev-xipher-cbom-extension-00`, is a design input.
It does not become a registry contract without field-level review.

## 5. Classification policy

IANA `Recommended` values have distinct meanings:

| Value | Source meaning | QuReddy treatment |
|---|---|---|
| `Y` | Recommended | No weakness inferred from this field |
| `N` | No general IETF recommendation | No weakness inferred from this field alone |
| `D` | Discouraged | Sourced discouraged rating |

Treating every `N` entry as weak creates false findings. A suite may have limited applicability or
lack IETF consensus while remaining suitable for its defined use case. QuReddy rates a suite from
the complete cited evidence, including `D` status and algorithm-specific RFCs.

Classical and quantum posture remain independent axes:

- Classical weakness covers defects relevant today, including RC4, DES, 3DES/SWEET32, NULL,
  EXPORT, and applicable MD5 uses.
- Quantum vulnerability covers classical key establishment or authentication exposed to a future
  cryptographically relevant quantum computer.

SWEET32 illustrates why facts must remain precise. Effective key strength and block size are
different properties. CycloneDX `classicalSecurityLevel` can represent a classical security level.
QuReddy retains `block_bits` as a custom fact because CycloneDX 1.7 has no direct block-size field.

## 6. Detection and probe profiles

The native selector offers reviewed two-byte IANA suite identifiers in a ClientHello, reads one
bounded TLS record, validates any selected suite against the offer, and stops after ServerHello.
It performs no key exchange.

```text
resolved candidate IDs
        |
        +--> pinned OpenSSL when the provider can offer the candidate
        |
        +--> native ServerHello selector for reviewed excluded candidates
        |
        v
canonical attempt observation
        |
        v
OFFERED | NOT_OFFERED | NOT_TESTABLE | AMBIGUOUS | NOT_ATTEMPTED
```

Probe execution uses a separate strict JSON plan (#599). The plan pins the registry identity and
digest and owns selectors, backends, bounds, ordering, timeouts, and coverage. Selectors resolve to
an immutable ordered candidate list before network access. The result records that list.

Planned built-in profiles are:

| Profile | Scope |
|---|---|
| `default` | Current bounded production scan |
| `weak-ciphers` | Reviewed discouraged and classically weak candidates |
| `pqc` | Reviewed PQC and hybrid candidates |
| `full` | Every assigned, eligible, probeable registry entry for enabled TLS axes |
| `atm` | Planned deployment-context schedule owned by #623 |

`full` excludes unassigned, reserved, private-use, and GREASE values. It never disables budgets.
A budget stop produces `NOT_ATTEMPTED` entries and a partial coverage receipt.

The transport contract is `tls-ready-byte-stream`. Direct TLS satisfies it directly. STARTTLS
requires a fresh upgraded transport for every attempt. Until #710 approves that ownership seam,
OpenSSL-excluded STARTTLS candidates remain explicit incomplete coverage.

## 7. Alternatives considered

Two designs were pressure-tested. Scores are 1 through 5, multiplied by the stated weight.

| Criterion | Weight | Combined crypto and compliance file | Compact registry plus downstream policy packs |
|---|---:|---:|---:|
| QuReddy runtime independence | 25 | 2 | 5 |
| One owner per crypto fact | 20 | 5 | 5 |
| Framework churn and licensing isolation | 20 | 2 | 5 |
| Policy review and OSCAL validation | 20 | 3 | 5 |
| Cross-product identity integrity | 15 | 5 | 4 |
| **Weighted score** | **100** | **3.30** | **4.85** |

The compact registry with downstream policy packs is selected. A combined file simplifies local
cross-reference validation. It also makes the scanner distribute framework-derived content and
validate data it never consumes. Stable IDs, pinned digests, and cross-product contract tests
preserve identity across the selected boundary.

## 8. Registry and policy ownership

```text
LEGEND
🟨 external authority or tool    🟦 acquisition
🟩 canonical QuReddy data        🟪 scoring policy
🟧 output                        🟥 prohibited path


+--------------------------------------------------------------+
| 🟨 AUTHORITATIVE SOURCES                                     |
|                                                              |
|  IANA       RFCs        NIST        MITRE CWE    CycloneDX   |
|  Y/N/D      Weaknesses  PQ status   Taxonomy     CBOM names  |
+-----+---------+-----------+------------+------------+--------+
      +---------+-----------+------------+------------+
                              |
                              v
+--------------------------------------------------------------+
| 🟩 REVIEWED IMPORT                                            |
|                                                              |
|  Pin source URI + release + digest + license + exact clause  |
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
| 🟩 qureddy-crypto-registry.json                               |
|                                                              |
|  algorithms       wire identities       sourced ratings      |
|  posture IDs      reason codes          curated CWE refs     |
+-----------------------+--------------------------------------+
                        | classification lookup
                        |
          +-------------+----------------------+
          |                                    |
+---------v-------------------+     +----------v----------------+
| 🟦 STANDARD SCAN            |     | 🟦 DEEP OR VULN SCAN       |
|                             |     |                           |
|  Native selector            |     |  External testssl.sh      |
|  Pinned OpenSSL             |     |  --deep or --vuln         |
+---------+-------------------+     +----------+----------------+
          |                                    |
          | observations                       | testssl JSON
          |                                    |
          |                         +----------v----------------+
          |                         | 🟦 TESTSSL ADAPTER           |
          |                         |                           |
          |                         | tool ID -> canonical type |
          |                         | preserve raw severity     |
          |                         | preserve CWE and CVE      |
          |                         | record tool version       |
          |                         +----------+----------------+
          |                                    |
          +----------------+-------------------+
                           |
                           v
+--------------------------------------------------------------+
| 🟩 CANONICAL OBSERVATIONS                                     |
|                                                              |
|  offered          not_offered       not_testable             |
|  ambiguous        not_attempted     vulnerable/not_vulnerable|
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
| 🟩 CANONICAL FINDINGS                                         |
|                                                              |
|  finding_type      reason_codes       posture_ids            |
|  evidence_refs     CWE/CVE refs        source provenance      |
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
| 🟩 CAPABILITY ASSESSMENTS                                     |
|                                                              |
|  Key establishment       Authentication                     |
|  Symmetric strength      Downgrade resistance               |
|  Classical hygiene                                          |
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
| 🟪 grading-policy.json                                        |
|                                                              |
|  weights + coverage gate + grade bands + visible caps        |
|                                                              |
|  CWE does not directly subtract points                       |
|  testssl severity does not override QuReddy policy           |
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
| 🟪 QUANTUM READINESS RESULT                                  |
|                                                              |
|  Score     Grade     Assurance     Coverage                  |
|  Dimension scores     Applied caps     Evidence references   |
+----------+------------------+-------------------+-------------+
           |                  |                   |
           v                  v                   v
     +-----------+      +-----------+      +-------------+
     | 🟧 OUTPUT |      | 🟧 OUTPUT |      | 🟧 OUTPUT   |
     | Rich      |      | JSON      |      | SARIF       |
     | summary   |      | JSONL     |      | findings    |
     +-----------+      +-----------+      +-------------+

       Registry + observations -------------> 🟧 CBOM inventory
       Findings + evidence -----------------> 🟧 mint-oscal/Enterprise


🟥 PROHIBITED PATHS

 testssl severity ----------------X----------> score
 raw CWE count -------------------X----------> point deduction
 compliance mapping --------------X----------> crypto registry
 endpoint score ------------------X----------> CSA QRI level
```

Plain-text path: authoritative sources enter a reviewed import, which builds the crypto registry.
Native, OpenSSL, and planned external testssl probes produce observations. The registry interprets
those observations into canonical findings and capability assessments. The grading policy consumes
the assessments. Renderers only project the canonical result.

Issue #722 tracks the planned testssl adapter. It preserves testssl tool ID, version, raw severity,
CVE, and CWE as imported evidence. Raw severity and CWE counts cannot directly change the score.
Registry ratings and the grading policy remain the interpretation authorities.

Complete review fixtures in `docs/architecture/examples/` cover the registry, probe plan, grading
policy, result receipt, and CSA QRI evidence map. QuReddy emits their stable identities and digests.
Mint-oscal owns framework mappings and OSCAL construction (#630, #718). Enterprise owns
organizational scope and approvals.

The [crypto registry reference](../reference/crypto-registry.md) defines the proposed fields,
validation rules, consumer obligations, and compatibility policy.

## 9. Grading and index alignment

The registry and canonical assessments enable a deterministic endpoint score (#669). The score is
a third policy file because weights, caps, and grade bands are interpretation rules. Probe profiles
cannot change the score for identical observations.

The proposed QuReddy Quantum Readiness Score aligns its bands to the published `open-quantum-secure`
scale:

| Score | Grade |
|---:|:---|
| 95 through 100 | A+ |
| 85 through 94 | A |
| 70 through 84 | B |
| 50 through 69 | C |
| 30 through 49 | D |
| 0 through 29 | F |
| omitted | U, insufficient evidence |

The source at commit `db003740b3d1cccd443ee2750f75bc332747751e` supplies the bands and a
reproducible finding-count algorithm. QuReddy adopts only the bands. The source algorithm returns
`100/A+` for zero findings, changes score with the number of findings, and has no acquisition
coverage gate. Those properties can reward an empty or under-covered scan. QuReddy instead uses
canonical dimensions, coverage gates, and visible caps in its own versioned policy. The result
reports score, grade, assurance, coverage, dimension reasons, caps, evidence references, and
grading-policy version. Unknown or untested input cannot be converted to zero.

The Singapore Cyber Security Agency Quantum Readiness Index V1 is a different model. It assesses
organizational maturity at L0 through L3 across Risk Assessment, Governance, Technology, Training and
Capability, and External Engagements. QuReddy can supply evidence for parts of Risk Assessment
and Technology, but cannot determine an overall CSA QRI level. Enterprise may map that evidence into
a full organizational assessment without presenting the endpoint grade as CSA QRI.

CBOM remains a crypto inventory. JSON and Rich may present the score directly. A CBOM projection
requires a reviewed namespaced CycloneDX property and cannot appear inside standard
`algorithmProperties`.

## 10. Consequences

- The design permits native testing of reviewed RC4, DES, and 3DES suites excluded by OpenSSL.
- The coverage contract adds a terminal state for every resolved candidate.
- Summary, CBOM, and hygiene will derive classification from one registry.
- IANA `N` entries will not create weak-cipher findings without separate evidence.
- TLS, SSH, IKE, and future TLS-ready transports can reuse algorithm facts and posture IDs.
- Profiles can select bounded acquisition schedules without changing interpretation.
- QuReddy keeps OSCAL and framework release cadences outside its runtime.
- Endpoint scoring remains attributable and versioned. CSA QRI remains an organizational
  assessment owned by the downstream product lane.
- The design introduces three versioned data contracts and requires cross-contract compatibility
  tests, source pinning, and release review.

## 11. Revisit when

Revisit this decision when any of these conditions occurs:

1. CycloneDX adds standard fields that replace a QuReddy extension.
2. The IETF adopts a CBOM extension with compatible registry or assessment semantics.
3. STARTTLS cannot satisfy the `tls-ready-byte-stream` contract without duplicated upgrade code.
4. A supported consumer requires framework mappings in the scanner artifact.
5. The selected score bands change or a standards body publishes a reproducible endpoint scale.
6. CSA publishes a machine-readable QRI model suitable for governed downstream ingestion.

## 12. References

- [IANA TLS Parameters](https://www.iana.org/assignments/tls-parameters/), TLS Cipher Suites.
- [RFC 9847](https://www.rfc-editor.org/rfc/rfc9847), IANA registry updates for TLS and DTLS.
- [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325), recommendations for TLS and DTLS.
- [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996), TLS 1.0 and TLS 1.1 deprecation.
- [RFC 9155](https://www.rfc-editor.org/rfc/rfc9155), MD5 and SHA-1 signature-hash deprecation.
- [RFC 5469](https://www.rfc-editor.org/rfc/rfc5469), DES and IDEA suite deprecation.
- [RFC 7465](https://www.rfc-editor.org/rfc/rfc7465), RC4 prohibition.
- [RFC 10015](https://www.rfc-editor.org/rfc/rfc10015), obsolete TLS 1.2 key establishment.
- [NIST IR 8547 initial public draft](https://doi.org/10.6028/NIST.IR.8547.ipd), transition to
  post-quantum cryptography standards.
- [CycloneDX 1.7 JSON Schema](https://cyclonedx.org/schema/bom-1.7.schema.json).
- [`draft-dev-xipher-cbom-extension-00`](https://datatracker.ietf.org/doc/draft-dev-xipher-cbom-extension/).
- [Open Quantum Secure at the reviewed commit](https://github.com/jimbo111/open-quantum-secure/blob/db003740b3d1cccd443ee2750f75bc332747751e/pkg/quantum/score.go), published Quantum Readiness Score bands and reference calculation.
- [Singapore CSA Quantum Readiness Index V1](https://www.csa.gov.sg/resources/publications/quantum-safe-handbook-and-quantum-readiness-index/).
- QuReddy issues #591, #599, #616, #623, #630, #669, #671, #672, #700, #701, #705, #706, #708, #709, #710, #718, and #722.
