<!-- SPDX-License-Identifier: Apache-2.0 -->

# Posture status model

QuReddy reports several related but independent security statuses. This page explains how
observations become findings, signals, posture axes, HNDL assessments, and CISO-facing
evaluation text. It also distinguishes the implemented global IKE boundary from the proposed
scoped IKE-SA assessment: an IKE-SA result is not an assessment of the complete IPsec tunnel.

## Contents

1. [The status circuit](#1-the-status-circuit)
2. [Status families](#2-status-families)
3. [Many-to-many examples](#3-many-to-many-examples)
4. [IKE scope boundary](#4-ike-scope-boundary)
5. [Output contract](#5-output-contract)
6. [Current implementation boundary](#6-current-implementation-boundary)

## 1. The status circuit

One acquisition creates one canonical result. The result is then projected into independent
status dimensions. A status in one dimension does not overwrite a status in another.

```text
 Evidence ──many──► Findings ──many──► Semantic signals
      │                  │                    │
      │                  │                    ├──► Readiness rollup
      │                  │                    ├──► PQC support
      │                  │                    ├──► Key-exchange axis
      │                  │                    ├──► Downgrade axis
      │                  │                    ├──► Authentication axis
      │                  │                    ├──► Protocol-hygiene axis
      │                  │                    └──► HNDL assessment
      │                  │
      └──────────── provenance and evidence references

                         Canonical ScanResult
                                  │
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
               Rich             JSON/JSONL         CBOM
```

The arrows are fan-out, not separate scans. Renderers consume the same result and do not
re-probe. Format adapters may project canonical facts into format-specific structures, but
posture values come from the canonical interpretation rather than renderer-specific evaluation.

## 2. Status families

| Family | Values | Question answered |
|---|---|---|
| Finding readiness | `quantum_safe`, `transitional_hybrid`, `quantum_vulnerable`, `classically_weak`, `unknown`, `not_applicable` | What does this finding say about the observed algorithm or protocol? |
| PQC support | `pure_pq_observed`, `hybrid_observed`, `classical_only_observed`, `unknown`, `not_testable` | What key-exchange capability was observed? |
| Key-exchange axis | `pure_pq`, `hybrid`, `classical`, `unknown`, `not_testable` | What key-exchange posture was observed? |
| Downgrade resistance | `acceptable`, `action_needed`, `unknown`, `not_testable` | Is fallback or downgrade control adequate? |
| Authentication | `classical`, `pure_pq`, `not_applicable`, `not_testable` | What authentication evidence was observed? |
| Protocol hygiene | `acceptable`, `action_needed`, `unknown`, `not_testable` | Does present-day protocol hygiene need work? |
| HNDL exposure | `protected`, `protected_defeasible`, `at_risk`, `unknown` | What can be concluded about future decrypt-later exposure? |
| Hygiene status | `ok`, `action_needed`, `weak`, `unknown` | How urgent is current-day remediation? |
| Effective readiness | Same `Readiness` vocabulary | What is the scan-level readiness rollup? |

These families are intentionally not interchangeable. For example, `classical_only_observed`
is a PQC-support result, while `action_needed` is a remediation status and `at_risk` is an
HNDL assessment.

## 3. Many-to-many examples

One classical key-exchange finding can drive several independent outputs:

```text
 tls.kex.classical
        │
        ├──► finding readiness       = quantum_vulnerable
        ├──► PQC support             = classical_only_observed
        ├──► key-exchange axis       = classical
        ├──► downgrade resistance    = action_needed
        ├──► hygiene status          = action_needed
        └──► HNDL exposure           = at_risk
```

Two findings can combine into a different set of outputs:

```text
 tls.kex.hybrid  +  tls.legacy.protocol_offered
        │
        ├──► PQC support             = hybrid_observed
        ├──► key-exchange axis       = hybrid
        ├──► protocol hygiene        = action_needed
        └──► HNDL exposure           = protected
```

The same evidence may therefore contribute to more than one axis, while a single axis may
depend on several findings and evidence records.

## 4. IKE scope boundary

An IKE scan observes IKE negotiation. It does not, by itself, prove the complete IPsec
security association, authentication, Phase 2, ESP/AH, or traffic-protection posture.

The global boundary is implemented: IKE key-establishment evidence leaves the endpoint-level
HNDL value `unknown`. The scoped IKE-SA assessment shown below is the proposed contract tracked
by [issue #625](https://github.com/BreachSAFE/qureddy/issues/625), not a production model.

```text
 IKE proposal and response evidence
                 │
                 ▼
        Scoped IKE-SA assessment
                 │
                 ├── classical KE  ──► at_risk
                 ├── hybrid KE     ──► protected_defeasible
                 └── incomplete    ──► unknown

 Complete IPsec tunnel posture
                 └──────────────────► unknown until separately evidenced
```

The global endpoint HNDL field therefore must not claim `protected` or `at_risk` from IKE-SA
evidence alone. A future scoped assessment will carry the IKE-SA conclusion with its own reason
codes and evidence references.

Proposed IKE interpretation:

| Observation | Global HNDL | Proposed scoped IKE-SA HNDL |
|---|---|---|
| Classical KE accepted | `unknown` | `at_risk` |
| Hybrid KE accepted | `unknown` | `protected_defeasible` |
| Silence or partial scan | `unknown` | `unknown` |
| No classical result | `unknown` | `unknown` |

`quantum_vulnerable` on an IKE finding is not the same field as global endpoint HNDL. It
describes the finding or readiness rollup; it does not prove the complete IPsec tunnel is
decryptable later.

## 5. Output contract

All output formats consume the same canonical result:

```text
ScanResult
  └── interpretation
       ├── effective
       ├── axes
       ├── hndl_exposure              # global scope
       ├── hygiene_status
       ├── reason_codes
       └── evidence_refs
```

When scoped IKE assessments are implemented, they must be added to the canonical interpretation
model, not calculated separately by Rich, JSON, JSONL, or CBOM renderers. Each scoped assessment
must identify its scope, status, reason codes, and evidence references.

CBOM remains an inventory and provenance projection. It may record the IKE protocol and exact
observed algorithm proposals, but it must not claim overall IPsec protection from an IKE-SA
observation.

## 6. Current implementation boundary

The current shared evaluator has these implemented contracts:

- PQC support, posture axes, HNDL exposure, and hygiene status serialize as distinct fields.
- KEX semantic signals require canonical finding types and matching readiness values.
- The evaluator normalizes the resolved protocol before applying posture policy. IKE
  key-establishment evidence keeps global `hndl_exposure` at `unknown`; regression tests cover
  explicit, evidence-derived, and finding-derived protocol values.
- Rich, JSON, JSONL, and CBOM consume the canonical scan result.

The following work is planned rather than implemented:

- `ScopedHndlAssessment` is not yet a field on `ScanInterpretation`; issue #625 tracks it.
- The broader protocol examples and reference-document reconciliation remain in
  [issue #628](https://github.com/BreachSAFE/qureddy/issues/628). This page documents the status
  families and IKE boundary but does not complete that issue.

Until the scoped model is added, CISO-facing text must not present a scoped IKE-SA status as
though it were the global endpoint HNDL posture.
