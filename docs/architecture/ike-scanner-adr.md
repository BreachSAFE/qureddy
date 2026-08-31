<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR: IKE HNDL evidence scanner

[![Architecture decision](https://img.shields.io/badge/QuReddy-architecture%20decision-8250df?style=flat-square)](https://github.com/BreachSAFE/qureddy/blob/main/docs/architecture/ike-scanner-adr.md)

**Tag:** `[546]`
**Status:** Accepted; implementation pending
**Scope:** QuReddy native IKE observation and canonical output integration
**Issue:** [#546](https://github.com/BreachSAFE/qureddy/issues/546)

PR #564 merged this version-controlled ADR as the sole normative IKE architecture and data
contract. Issue #546 is the delivery tracker, not a second specification. Later architectural
changes require a reviewed ADR update; an issue edit or comment cannot silently override this
file. Earlier issue-body drafts and comments are historical material only and are not
implementation authorities.

## Contents

1. [Decision summary](#1-decision-summary)
   1. [Capability matrix](#11-capability-matrix)
2. [Problem and non-goals](#2-problem-and-non-goals)
   1. [Problem](#21-problem)
   2. [In scope](#22-in-scope)
   3. [Out of scope for the first release](#23-out-of-scope-for-the-first-release)
3. [Architecture](#3-architecture)
   1. [Component topology](#31-component-topology)
   2. [Dependency direction](#32-dependency-direction)
   3. [One acquisition, one canonical result](#33-one-acquisition-one-canonical-result)
4. [Canonical data contract](#4-canonical-data-contract)
   1. [Canonical model ownership](#41-canonical-model-ownership)
   2. [Protocol-private boundary](#42-protocol-private-boundary)
   3. [Result integration](#43-result-integration)
   4. [Contract ownership gates](#44-contract-ownership-gates)
5. [IKE protocol contract](#5-ike-protocol-contract)
   1. [Probe behavior](#51-probe-behavior)
   2. [Evidence ladder](#52-evidence-ladder)
   3. [Response binding requirements](#53-response-binding-requirements)
6. [CLI contract](#6-cli-contract)
   1. [Command](#61-command)
   2. [Proposed options](#62-proposed-options)
   3. [Exit codes](#63-exit-codes)
7. [Evidence and HNDL evaluation](#7-evidence-and-hndl-evaluation)
   1. [Policy inputs](#71-policy-inputs)
      1. [Scoped HNDL assessment](#711-scoped-hndl-assessment)
      2. [Semantic-signal naming contract](#712-semantic-signal-naming-contract)
   2. [Required semantic rules](#72-required-semantic-rules)
   3. [Output parity](#73-output-parity)
8. [External validator contract](#8-external-validator-contract)
   1. [EnXemble role](#81-enxemble-role)
   2. [Provenance and disagreement](#82-provenance-and-disagreement)
9. [File-level implementation plan](#9-file-level-implementation-plan)
   1. [QuReddy files to change](#91-qureddy-files-to-change)
   2. [Tests and fixtures to add](#92-tests-and-fixtures-to-add)
   3. [EnXemble files](#93-enxemble-files-separate-repositoryfollow-up)
10. [Test and pressure-test plan](#10-test-and-pressure-test-plan)
    1. [Required lab matrix](#101-required-lab-matrix)
    2. [Real CLI commands](#102-real-cli-commands)
11. [Security and safety controls](#11-security-and-safety-controls)
12. [Alternatives and trade-offs](#12-alternatives-and-trade-offs)
13. [Acceptance criteria](#13-acceptance-criteria)
14. [Rollout and compatibility](#14-rollout-and-compatibility)
15. [Open decisions](#15-open-decisions)
16. [Implementation handoff and ownership](#16-implementation-handoff-and-ownership)
    1. [File and component map](#161-file-and-component-map)
    2. [Single-owner data model](#162-single-owner-data-model)
    3. [Per-issue working agreement](#163-per-issue-working-agreement)
    4. [Milestone exit contract](#164-milestone-exit-contract)
17. [Implementation quality bar](#17-implementation-quality-bar)
    1. [References](#171-references)

## 1. Decision summary

QuReddy will add a native, observation-only IKE scanner behind the existing
collector and canonical-result seams. The first production slices are bounded to
unauthenticated IKEv1 discovery and IKEv2 `IKE_SA_INIT` observation. They do not
establish a tunnel, authenticate, recover a PSK, or claim completed PQ
protection.

```text
qureddy scan ike TARGET
        |
        v
    IKEProbeRequest
        |
        v
    NativeIKECollector
        |
        v
    IKEParser + response binding
        |
        v
    bound IKEProposalObservation(s) + typed failure
        |
        v
    shared evaluator -> interpretation/findings
        |
        v
    IKEScanner constructs one immutable ScanResult
        |
        v
    NativeIKECollector wraps the same result in CollectionResult
        |
        +--> rich
        +--> json
        +--> jsonl
        +--> CycloneDX CBOM (after CBOM mapping gate)
```

`ike-scan` is optional and external. EnXemble may run it as an independent
validator/corroborator for IKEv1 transform and legacy-mode evidence. It is not a
QuReddy runtime dependency, is not the authoritative PQ scanner, and does not
write CBOM directly.

The implementation is intentionally staged under the delivery sequence in #546:

1. #549 target parsing/capability registration, then #550 catalog and exact identity;
2. #551 bounded UDP/codec and the observation-scoped provider boundary;
3. #552 IKEv1 Main/Aggressive observation and Historic plus authentication-method-specific
   identity/credential findings;
4. #553 IKEv2 binding, unchanged attributes, and inconsistent-selection termination;
5. #554 canonical findings and Rich/JSON/JSONL/CBOM parity;
6. #476 canonical semantic/output conformance;
7. #477 installed CLI flags, exit codes, and deterministic output;
8. #556 package/image/docs release verification, consuming #561 pinned-lab evidence.

Post-MVP milestone `0.14.0 - IKE PQC and Discovery Parity`: #555 live ML-KEM-768/1024 and legal
ADDKE selection, #562 completion, and #563 discovery parity.

Protected `IKE_INTERMEDIATE`/ADDKE completion is planned in the `0.14.0 - IKE PQC and Discovery Parity`
milestone and owned by
[#562](https://github.com/BreachSAFE/qureddy/issues/562). EnXemble validation is owned by
the separate [EnXemble issue #51](https://github.com/BreachSAFE/enxemble/issues/51).

No stage may label an endpoint `PROTECTED` from an IKE capability notification
or unauthenticated proposal observation.

### 1.1 Capability matrix

This matrix is the acceptance boundary, not a promise that the current branch already implements
the feature. `0.13` is the pre-PQC release; `0.14` adds the explicitly deferred parity work.

| Capability | 0.13 pre-PQC | 0.14 parity | Evidence/output |
|---|---|---|---|
| IKEv1 Main Mode | required | retained | exact offered/selected Phase-1 tuples |
| IKEv1 Aggressive Mode | required | retained | Historic; identity exposure except public-key-encryption authentication; PSK offline-guessing finding |
| IKEv2 `IKE_SA_INIT` | required | retained | exact ENCR/PRF/INTEG/KE tuples and notifications |
| IKEv2 `IKE_INTERMEDIATE` | not tested | planned | protected completion only after #562 gates |
| ADDKE1--ADDKE7 | catalog only | planned #555 | slot, wire ID, tuple, coverage |
| ML-KEM-512 / ID 35 | catalog-only `not_tested` | unchanged | never scheduled or attempted |
| ML-KEM-768 / ID 36 | catalog-only `not_tested` | planned #555 | live ADDKE/IKE_INTERMEDIATE selection evidence when supported |
| ML-KEM-1024 / ID 37 | catalog-only `not_tested` | planned #555 | live ADDKE/IKE_INTERMEDIATE selection evidence when supported |
| NAT-T Vendor-ID / NAT-D / UDP 4500 | required | retained | bounded metadata and framing evidence |
| COOKIE / INVALID_KE_PAYLOAD / NO_PROPOSAL_CHOSEN | required | retained | typed retry/rejection/unknown outcomes |
| Retransmission/backoff fingerprinting | bounded timing only | planned #563 | no GPL database; digest/timing provenance only |
| Rich / JSON / JSONL / CBOM / `--output-dir` | required | retained | one canonical `ScanResult` |
| Overall authenticated IPsec posture | always `UNKNOWN` | always `UNKNOWN` | IKE-SA scope may be classified separately |

ML-KEM-768/1024 selection is not scheduled in the initial unauthenticated `IKE_SA_INIT` profile;
the 0.14 path is legal ADDKE/IKE_INTERMEDIATE negotiation with the matching capability
notification and peer-specific MTU/fragmentation proof. ML-KEM-512 remains catalog-only,
`not_tested`, and outside active probing. TLS and SSH remain existing compatibility baselines;
this ADR does not change their acquisition
or serialized output. IKE_AUTH, credentials/XAUTH, Child-SA, ESP/AH, traffic selectors, tunnel
establishment, PSK recovery, and raw packet/secret retention are not extractable by this design.

## 2. Problem and non-goals

### 2.1 Problem

An endpoint can expose classical IKE algorithms or accept a weaker mode even if
its preferred configuration supports stronger or post-quantum mechanisms. That
creates harvest-now-decrypt-later (HNDL) and downgrade evidence. QuReddy needs a
repeatable, machine-readable observation of what a responder actually accepts,
with enough protocol detail for a security engineer and a bounded interpretation
for a CISO.

### 2.2 In scope

- UDP/500 and UDP/4500 target parsing, timeout, retry, and bounded retransmission.
- IKEv1 Main/Aggressive discovery evidence where the responder exposes it.
- IKEv2 `IKE_SA_INIT` proposal and notify observation.
- Protocol version, exchange type, mode, encryption, integrity/PRF, DH/KE group,
  NAT-T behavior, response state, and provenance.
- Explicit outcomes: `accepted`, `rejected`, `unknown`, and `not_tested` coverage.
- ML-KEM-512/ID 35 may be retained as lossless catalog metadata only. It is never
  scheduled, attempted, or used in a readiness claim. ML-KEM-768/1024 are the
  only in-scope PQ parameter sets.
- Canonical Rich, JSON, JSONL, and later CBOM projections.
- EnXemble-side `ike-scan` validation is a separate consumer concern; it never
  writes CBOM and never replaces QuReddy evidence.

### 2.3 Out of scope for the first release

- Authentication, XAUTH credentials, PSK recovery, `HASH_R`, or password testing.
- Tunnel establishment, child-SA negotiation, packet decryption, or traffic capture.
- Claiming that a selected ADDKE/ML-KEM transform completed successfully.
- Implementing cryptographic primitives in QuReddy.
- Bundling Go, Rust, C, or `ike-scan` into the Python wheel.
- Treating UDP silence as proof that the endpoint is secure or unsupported.
- Direct tool output to CBOM, or a second posture/evaluation model.

## 3. Architecture

### 3.1 Component topology

```text
CLI: scan ike
    -> IKE target parser
    -> IKEProbeRequest
    -> CollectorRegistry
    -> NativeIKECollector
    -> bounded UDP transport
    -> IKE parser and response binder
    -> bound IKEProposalObservation
    -> shared evaluator builds interpretation/findings
    -> IKEScanner constructs one immutable ScanResult
    -> NativeIKECollector wraps it in CollectionResult
         +--> Rich
         +--> JSON
         +--> JSONL
         +--> CycloneDX CBOM
         +--> --output-dir bundle

EnXemble ike-scan validator -- corroboration/provenance only --> evaluator
```

### 3.2 Dependency direction

```text
CLI
  -> target/request validation
  -> capability registry
  -> native IKE collector
  -> IKE parser and typed observations
  -> shared policy/evaluator
  -> shared renderers

EnXemble descriptor
  -> QuReddy primary run
  -> optional ike-scan validator
  -> validator status and provenance
```

The IKE package owns IKE vocabulary and packet parsing. `core` owns protocol-
neutral source, provenance, failure, and result types. Renderers never open a
socket or parse IKE bytes. EnXemble validation never replaces QuReddy evidence.

### 3.3 One acquisition, one canonical result

```text
CLI -> Registry: select NativeIKECollector
NativeIKECollector.collect() -> NativeIKECollector.scan()
NativeIKECollector.scan() -> IKEScanner.scan()
IKEScanner -> UDP transport/codec/binder: bounded acquisition
Transport/codec/binder -> IKEScanner: bound observation or typed failure
IKEScanner -> shared evaluator: neutral facts
Shared evaluator -> IKEScanner: interpretation and findings
IKEScanner -> NativeIKECollector: one immutable ScanResult
NativeIKECollector -> CLI: CollectionResult carrying that same ScanResult
CLI -> Output projections: read CollectionResult.scan_result and render once
Output projections -> caller: Rich / JSON / JSONL / CBOM / bundle
```

`--output-dir` fans out projections from the same `ScanResult`; it never repeats
the network operation.

## 4. Canonical data contract

### 4.1 Canonical model ownership

This section is the complete public IKE model contract. The implementation may split these
models across modules, but it must preserve the names, field meanings, enum values, validation,
and ownership below. All public models are immutable. Optional additions are excluded from
serialization when empty so existing TLS and SSH `qureddy.scan.v1` bytes remain unchanged.

| Type | Normative values |
|---|---|
| `NetworkTransport` | `tcp`, `udp` |
| `IKEVersion` | `1`, `2` |
| `IKEExchange` | `main`, `aggressive`, `ike_sa_init` |
| `IKESlot` | `primary`; `addke1` through `addke7` are reserved for 0.14 |
| `IKENatT` | `auto`, `off`, `force` (configuration only) |
| `AlgorithmRole` | `encryption`, `hash`, `prf`, `integrity`, `authentication`, `key_exchange` |
| `AlgorithmStatus` | `current`, `deprecated`, `private`, `unknown`, `not_allowed` |
| `NegotiationOutcome` | `accepted`, `rejected`, `unknown` |
| `NegotiationReason` | `selected`, `explicit_notify`, `no_response`, `filtered`, `rate_limited`, `malformed`, `response_mismatch`, `ambiguous_selection`, `retry_exhausted`, `budget_exhausted`, `deadline_exhausted`, `provider_unavailable`, `profile_excluded` |
| `AttemptRole` | `initial`, `cookie_retry`, `invalid_ke_retry`, `retransmission` |
| `AttemptOutcome` | `bound`, `unbound`, `no_response`, `malformed`, `send_failed` |
| `CoverageState` | `accepted`, `rejected`, `unknown`, `not_tested` |
| `NatMechanism` | `none`, `ikev1_natd`, `ikev2_notify` |
| `NatMatch` | `not_tested`, `absent`, `match`, `mismatch` |
| `NatTranslation` | `not_tested`, `none_detected`, `detected` |
| `NonEspMarker` | `not_applicable`, `absent`, `present` |
| `PortFloat` | `not_tested`, `not_attempted`, `attempted`, `accepted`, `unavailable` |

`not_tested` is a coverage state on a `CoverageEntry`, never a
`NegotiationOutcome` and never a fabricated observation. No code path may
construct an `IKEProposalObservation` for a `not_tested` row.

**Attempt-level evidence is lossless and never collapsed.** Every datagram the
scanner sends is one `IKEAttemptEvidence` with its own source port, SPI pair,
header fields, digests, and timing. A retry is a **new attempt with a new
`ordinal`** whose `parent_ordinal` names the attempt that provoked it, not a
mutation of the first. This is required by the protocol, not a preference:

- `COOKIE`: the initiator retries `IKE_SA_INIT` with the cookie
  (`rfc7296/rfc7296.txt:667`). Two datagrams, one logical proposal.
- `INVALID_KE_PAYLOAD`: the responder accepted the proposal and disagreed only
  about the key exchange group (`rfc7296/rfc7296.txt` §1.3, §3.10.1, interaction
  with COOKIE at line 149). Recording it as a rejection loses the fact that
  everything except the group was acceptable, so the first leg keeps
  `outcome=bound` with `reason=explicit_notify` and the retry carries
  `role=invalid_ke_retry`.
- Retransmission (`rfc7296/rfc7296.txt:323`) is `role=retransmission` and
  **must not create a second `IKEProposalObservation`**.

A failed binding followed by an accepted response is therefore two attempts on
one observation: `outcome=unbound` then `outcome=bound`. Both are retained. The
proposal-level `outcome` is derived from the attempt sequence and is `accepted`
only when the final bound attempt satisfies every §5.3 binding rule.

**Notifications are an ordered tuple, never a scalar.** A single response can
carry `NAT_DETECTION_SOURCE_IP`, `NAT_DETECTION_DESTINATION_IP`,
`INTERMEDIATE_EXCHANGE_SUPPORTED`, and `COOKIE` together, and
`rfc7296/rfc7296.txt:3570` states there **MAY be multiple**
`NAT_DETECTION_SOURCE_IP` payloads in one message. Order is as received.
`data_hex` is populated only for types on a bounded allowlist; every other
notification records `data_length` and `data_sha256` with `redacted=True`.
**COOKIE values, nonces, key shares, and authentication material are never
retained in a public model**, so a `COOKIE` notification carries its length and
digest and never its bytes.

**NAT-T is an observation, not a boolean.** The two IKE versions use different
mechanisms and `IKENatObservation` distinguishes them: IKEv1 sends NAT-D
payloads and requires the vendor ID in the first two Phase 1 messages
(`rfc3947/rfc3947.txt:178`, payloads at `:211`); IKEv2 uses
`NAT_DETECTION_SOURCE_IP` and `NAT_DETECTION_DESTINATION_IP` notifications
(`rfc7296/rfc7296.txt:3560`). `requested` records configuration only. A peer
that mandates NAT-T will not answer an initiator that omitted the vendor ID,
and that silence is indistinguishable from a filtered host without the peer
log, so it stays `unknown`.

**Coverage totals are derived.** `CoverageReceipt.entries` is the source of
truth and the integer fields are computed from it; an implementation must not
author a total independently. This is what lets a receipt answer *which* row
was not tested. ML-KEM-512 / ID 35 is the standing case: it appears as a
`CoverageEntry` with `state=not_tested`, `planned=False`, `attempted=False`,
and an `exclusion_reason`, and never as an observation.
The pre-PQC evidence level is the literal `selected`; completion levels require the 0.14 contract
change in #562 and do not exist in the 0.10 through 0.13 public model or provider interface.

```python
class IKETransformAttribute(BaseModel):
    attribute_type: int
    encoding: Literal["tv", "tlv"]
    value_hex: str
    ordinal: int

class AlgorithmObservation(BaseModel):
    registry: str
    wire_id: int
    name: str
    role: AlgorithmRole
    slot: IKESlot = IKESlot.PRIMARY
    key_size: int | None = None
    status: AlgorithmStatus

class IKETransformObservation(BaseModel):
    ordinal: int
    transform_number: int | None = None
    transform_type: int | None = None
    transform_id: int
    slot: IKESlot = IKESlot.PRIMARY
    attributes: tuple[IKETransformAttribute, ...] = ()
    algorithms: tuple[AlgorithmObservation, ...]

class IKEEndpoint(BaseModel):
    ip: str
    port: int = Field(ge=1, le=65535)

class IKEAttemptEvidence(BaseModel):
    """One concrete datagram exchange. Never merged, never summarized away."""
    ordinal: int = Field(ge=1)
    role: AttemptRole
    parent_ordinal: int | None = None
    source: IKEEndpoint
    destination: IKEEndpoint
    response_source: IKEEndpoint | None = None
    initiator_spi: str = Field(pattern=r"^[0-9a-f]{16}$")
    responder_spi: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")
    ike_version: IKEVersion
    exchange: IKEExchange
    flags_hex: str = Field(pattern=r"^[0-9a-f]{2}$")
    message_id: int = Field(ge=0)
    declared_length: int | None = None
    observed_length: int | None = None
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    sent_at_ms: int
    elapsed_ms: int = Field(ge=0)
    outcome: AttemptOutcome
    reason: NegotiationReason
    notifications: tuple[IKENotificationObservation, ...] = ()

class IKENotificationObservation(BaseModel):
    """Ordered as received. RFC 7296 line 3570 permits repeats of one type."""
    ordinal: int = Field(ge=0)
    notify_type: int = Field(ge=0, le=65535)
    notify_name: str | None = None
    protocol_id: int = 0
    spi_size: int = 0
    data_length: int = Field(ge=0)
    data_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    data_hex: str | None = None
    redacted: bool = True

class IKENatObservation(BaseModel):
    """IKEv1 NAT-D (rfc3947:211) and IKEv2 NAT_DETECTION_* (rfc7296:3560)."""
    requested: IKENatT
    mechanism: NatMechanism
    vendor_id_observed: bool = False
    vendor_id_sha256: tuple[str, ...] = ()
    source_payloads: int = Field(default=0, ge=0)
    destination_payloads: int = Field(default=0, ge=0)
    source_match: NatMatch = NatMatch.NOT_TESTED
    destination_match: NatMatch = NatMatch.NOT_TESTED
    translation: NatTranslation = NatTranslation.NOT_TESTED
    non_esp_marker: NonEspMarker = NonEspMarker.NOT_APPLICABLE
    port_float: PortFloat = PortFloat.NOT_TESTED
    observed_ports: tuple[int, ...] = ()

class CoverageEntry(BaseModel):
    """One catalog/profile row. The only place not_tested names a proposal."""
    catalog_version: str
    catalog_sha256: str
    profile_id: str
    profile_sha256: str
    proposal_id: str
    ike_version: IKEVersion
    exchange: IKEExchange
    planned: bool
    attempted: bool
    state: CoverageState
    reason: NegotiationReason | None = None
    exclusion_reason: str | None = None
    observation_ref: str | None = None

class IKEProposalObservation(BaseModel):
    proposal_id: str
    catalog_version: str
    catalog_sha256: str
    profile_id: str
    profile_sha256: str
    ike_version: IKEVersion
    exchange: IKEExchange
    transport: NetworkTransport
    destination_port: int
    nat: IKENatObservation
    proposal_number: int
    protocol_id: int
    doi: int | None = None
    situation_hex: str | None = None
    offered: tuple[IKETransformObservation, ...]
    selected: tuple[IKETransformObservation, ...] = ()
    outcome: NegotiationOutcome
    evidence_level: Literal["selected"] | None = None
    reason: NegotiationReason
    attempts: tuple[IKEAttemptEvidence, ...] = Field(min_length=1)
    duration_ms: int

class CoverageReceipt(BaseModel):
    """Totals are DERIVED from entries. Never authored independently."""
    protocol: Literal["ike"] = "ike"
    ike_version: IKEVersion
    exchange: IKEExchange
    catalog_version: str
    catalog_sha256: str
    profile_id: str
    profile_sha256: str
    entries: tuple[CoverageEntry, ...] = Field(min_length=1)
    planned: int
    attempted: int
    accepted: int
    rejected: int
    unknown: int
    not_tested: int
    complete: bool
    incomplete_reason: NegotiationReason | None = None

class CryptoProviderDependency(BaseModel):
    name: str
    version: str | None = None
    backend: str
    capabilities: tuple[str, ...] = ()
    failure_category: FailureCategory | None = None

type RuntimeDependency = OpenSSLDependency | CryptoProviderDependency

class ScanTarget(BaseModel):
    # Existing fields remain unchanged and in their existing order.
    transport: NetworkTransport = Field(
        default=NetworkTransport.TCP,
        exclude_if=lambda value: value is NetworkTransport.TCP,
    )

class Evidence(BaseModel):
    # Existing fields remain unchanged and in their existing order.
    ike_proposal: IKEProposalObservation | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )

class ScanResult(BaseModel):
    # Existing fields remain unchanged and in their existing order.
    dependencies: tuple[RuntimeDependency, ...]
    coverage: tuple[CoverageReceipt, ...] = Field(
        default_factory=tuple,
        exclude_if=lambda value: not value,
    )
```

**Delta against the current tree, measured on `main`.** None of the four
integration points exists yet, so every one is a new field and not a
modification of shipped bytes:

| Symbol | In `src/` today | Lands in |
|---|---|---|
| `OpenSSLDependency` | **yes**, 11 files | unchanged; must keep its exact serialized bytes |
| `RuntimeDependency` | **no**, 0 files | #473 |
| `CryptoProviderDependency` | **no**, 0 files | #597 |
| `ScanResult.coverage` | **no** field on `ScanResult` | #550 defines, #552/#553 populate |
| `ScanTarget.transport` | **no** | #463 |
| `Evidence.ike_proposal` | **no** | #550 |

An implementer must not assume `RuntimeDependency` is available to import.
Until #473 lands it, `dependencies` remains `tuple[OpenSSLDependency, ...]` and
TLS and SSH bytes are unchanged because the alias is a superset whose second
member never appears in a TLS or SSH result.

The additive integration points are `ScanTarget.transport`, `Evidence.ike_proposal`,
`ScanResult.coverage`, and the single `RuntimeDependency` alias. Issue #473 owns that alias and the
`CollectionResult`/`ScanProvenance` envelope. Issue #597 owns only
`CryptoProviderDependency` production and the private provider protocol. Both issues must import
or reference `RuntimeDependency`; neither may define another dependency union or provenance
shape. This two-member alias preserves existing OpenSSL objects and bytes while representing the
in-process PyCA provider. A repository-wide dependency-schema migration is separate work.

| Dependency option | Cost | Decision |
|---|---|---|
| Named two-member `RuntimeDependency` alias | Keeps two concrete models while preserving shipped TLS bytes | Selected |
| Unnamed unions repeated by each scanner | Allows issue-local drift and conflicting validators | Rejected |
| Generic dependency property bag | Loses field-level validation and changes shipped OpenSSL serialization | Rejected for IKE |

`proposal_number`, `protocol_id`, IKEv1 DOI/situation, the ordered wire transforms, and every typed
transform attribute are evidence-bearing identity, not display metadata. `value_hex` and
`situation_hex` are lowercase, even-length hexadecimal of the exact bounded value bytes.
Validators require `transform_number` and prohibit `transform_type` for IKEv1; they require
`transform_type` and prohibit `transform_number`, DOI, and situation for IKEv2. The normalized
`algorithms` tuple is derived from that exact wire representation. `key_size` must match the
corresponding attribute when present and is never the sole preservation of an attribute.

Proposal identity uses the following canonical JSON object and no smaller projection:

```json
{
  "schema": "qureddy.ike.proposal.v2",
  "version": "2",
  "exchange": "ike_sa_init",
  "proposal_number": 1,
  "protocol_id": 1,
  "doi": null,
  "situation_hex": null,
  "transforms": [
    {
      "ordinal": 0,
      "type": 1,
      "slot": "primary",
      "transform_number": null,
      "transform_id": 20,
      "attributes": [
        {"ordinal": 0, "type": 14, "encoding": "tv", "value_hex": "0100"}
      ]
    }
  ]
}
```

`proposal_id` always identifies the offered proposal. A response selection remains linked to that
ID and is accepted only when its `selected` wire transforms are an unchanged subset of the same
proposal; it does not replace or rewrite the offered identity. A batched request retains one
observation and proposal ID per offered proposal number, while `request_sha256` binds the complete
datagram.

Arrays remain in offered wire order; ordinals must be contiguous and duplicates remain present.
Serialize with `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True,
allow_nan=False)`, UTF-8 encode, and prefix the lowercase SHA-256 hex digest with `sha256:`.
Catalog names, normalized algorithm projections, target, timestamps, packet digests, transport,
NAT-T, and volatile cookies/SPIs are excluded because they do not change the wire proposal. They
remain independently bound and evidenced. Changing proposal number, protocol ID, DOI/situation,
transform order/number/type/ID/slot, attribute order/type/encoding/value, version, or exchange must
change `proposal_id`. #550 must add failing-before-fix collision vectors for each field before
implementing the catalog or binder.

The current QuReddy result seam is authoritative: `CollectionResult` is the collector wrapper,
`ScanResult` contains the evaluator output and is the renderer input, and the scoped HNDL tuple is
owned by `ScanResult.summary.interpretation.scoped_hndl_assessments`. No second
`IKEProposalObservation` graph,
renderer field, or protocol-specific result may be introduced.

`ScanTarget.transport` carries the explicit UDP/IKE representation while retaining TCP as the
default and omitting that default from existing TLS/SSH serialization. Target parsing rejects
invalid ports, unsupported schemes, bracket corruption, control characters, and ambiguous
host/port input before opening a socket.

Raw packet bytes, Vendor-ID bytes, secrets, credentials, PSK material, authentication hashes,
nonces, KE values, and keys never cross the bounded parser/redaction boundary. Only typed
metadata, bounded timing/counts, and one-way digests may enter the canonical result.

### 4.2 Protocol-private boundary

The codec, transport, sweep, and provider types are private implementation boundaries. Their
module owners and invariants are specified in sections 5 and 16; their exact field layout is an
implementation detail. They may carry bounded wire data internally, but they cannot be imported
by evaluators, renderers, CBOM mappers, or EnXemble. The only public handoff is an
`IKEProposalObservation` plus `CoverageReceipt` inside the canonical result. A selected tuple is
valid only after source/destination, IKEv1 initiator/responder cookie or IKEv2 SPI, version,
exchange, flags, message ID, retry state, and exact offered-proposal binding pass. IKEv2
`COOKIE`, `INVALID_KE_PAYLOAD`, and `NO_PROPOSAL_CHOSEN` are typed outcomes; they never become
implicit success or unsupported claims.

### 4.2.1 Fixed headers and payload boundaries

The parser implements the fixed wire headers from the vendored IKE sources, not a
protocol-specific approximation. The IKEv2 header is 28 octets:

```text
Initiator SPI (8) | Responder SPI (8)
Next Payload (1)  | Version (1: major/minor nibbles)
Exchange Type (1) | Flags (1)
Message ID (4)    | Length (4)
```

The IKEv1 ISAKMP header has the same field widths, with initiator/responder cookies
and ISAKMP version/mode semantics. The generic payload header is four octets:

```text
Next Payload (1) | Critical bit + reserved bits (1) | Payload Length (2)
```

`Payload Length` includes its four-octet header. A chain terminates only when
`Next Payload == 0`; every length, reserved field, version, exchange, flag, message
ID, SPI/cookie, and payload boundary is validated before a payload is interpreted.
The parser rejects truncation, declared-length overrun, zero/invalid lengths,
unknown critical payloads, and chains exceeding configured count/size limits.

The source of truth for these layouts is
`breachsafe-common:skills/skills/breachsafe-ipsec-conformance/references/citations.md`
§5, sourced from `rfc7296` and `rfc2408`. The corresponding normative behavior is
recorded in `rfc7296/rfc7296.txt` and `rfc2408/rfc2408.txt`; implementers MUST cite
those vendored files when changing the codec.

### 4.3 Result integration

`CollectionResult` remains the collector boundary, and its `scan_result` field carries
the single canonical result produced by `IKEScanner.scan()`. The existing `evidence`,
`findings`, and `provenance` members are compatibility projections of that result;
they must be populated only from it, never independently calculated. The IKE shape is:

```python
CollectionResult(
    collector="native-ike",
    collector_version="<package-version>",
    evidence=result.evidence,
    findings=result.findings,
    provenance=result.scan.provenance,
    failure=typed_failure_or_none,
    scan_result=result,  # the IKEScanner-created canonical ScanResult
)
```

`IKEScanner.scan()` gathers bound observations, passes neutral facts to the shared evaluator,
receives interpretation and findings, and then constructs `ScanResult` exactly once. The native
collector delegates to that scanner and wraps the returned immutable object. No evaluator runs
after construction, and no orchestrator creates a second `ScanResult` from `CollectionResult`
members. Tests must assert that the compatibility fields equal their corresponding values in
`collection.scan_result` and have no independent calculation path.
If the compatibility projections are eventually removed, that is a repository-wide
contract change; IKE must not introduce a third lifecycle.

The owning result field is additive and singular on the existing interpretation model:

```python
class ScanResult(BaseModel):
    # existing fields remain unchanged; interpretation remains under ScanSummary
    summary: ScanSummary

class ScanInterpretation(BaseModel):
    scoped_hndl_assessments: tuple[ScopedHndlAssessment, ...] = ()
```

The tuple contains at most one assessment per `HndlScope` and is reached as
`ScanResult.summary.interpretation.scoped_hndl_assessments`. It is the only source for IKE HNDL
scope in every output format. A convenience alias on `ScanResult`, if ever added, must be
read-only and non-serialized; no renderer may compute a second verdict.

### 4.4 Contract ownership gates

The architecture assigns each cross-cutting contract to one implementation issue. The ADR owns
the shape; the issue owns its implementation and tests:

| Contract | Sole implementation owner | Required gate |
|---|---|---|
| `RuntimeDependency`, `CollectionResult`, `ScanProvenance` | #473, with lifecycle wiring in #539 | one exact alias/envelope; compatibility projections cannot diverge |
| IKE enums and public observations | #550 | no duplicate public or renderer-local type |
| `IKEObservationProvider`, `CryptoProviderDependency` | #597 | exact surface in section 7.2; forbidden completion methods absent |
| Coverage truth: `CoverageEntry`, `CoverageReceipt` | #550 defines and emits entries; sweeps #552/#553 populate them | one entry per catalog/profile row; totals derived from entries, never authored |
| `IKEAttemptEvidence`, `IKEEndpoint`, `AttemptRole`, `AttemptOutcome` | #597 owns the codec/transport that produces attempts; #550 owns the public type | one attempt per datagram; retries are new ordinals, never mutations |
| `IKENotificationObservation` | #550 | ordered tuple; bounded allowlist for `data_hex`; no COOKIE, nonce, or key material retained |
| `IKENatObservation` and its five enums | #550 defines; #552 populates IKEv1 NAT-D, #553 populates IKEv2 notifications | one NAT model spanning both mechanisms; `nat_t: bool` must not reappear |
| Evaluator and scoped HNDL | #554, guarded by #598 | exact neutral facts and no favorable unauthenticated global posture |
| EnXemble validator provenance | #554 and EnXemble #51 | versioned corroboration status; never primary evidence |

No issue may introduce a second type for a row above. The public observation is the only IKE
object consumed by evaluation or output; wire/parser objects remain private.

## 5. IKE protocol contract

### 5.1 Probe behavior

The first implementation sends bounded, unauthenticated discovery/observation
requests. It may use IKEv1 Main/Aggressive discovery and IKEv2 `IKE_SA_INIT`, but
it never proceeds to authentication or tunnel setup. Each request has a unique IKEv1 initiator
cookie or IKEv2 initiator SPI, retry state, and exact offered-proposal identity.

```text
construct request
  -> send UDP/500 or UDP/4500
  -> accept only expected source and destination
  -> validate version, exchange, flags, IKEv1 cookies or IKEv2 SPIs, message ID, declared length
  -> validate retry state, offered-proposal identity, and payload bounds
  -> validate response against the offered proposal set
  -> classify response state
  -> preserve raw digest and typed observation
```

### 5.2 Evidence ladder

| State | Meaning | HNDL consequence |
|---|---|---|
| `accepted` | A bound response selected one exact offered proposal tuple | IKE-SA facts may be classified |
| `rejected` | A bound response explicitly rejected the offered batch | No algorithm-support claim |
| `unknown` | Silence, filtering, malformed data, or incomplete coverage | Overall posture remains `UNKNOWN` |
| `not_tested` | A catalog/profile row was not scheduled | Coverage accounting only |

An accepted classical key-exchange method is HNDL evidence under QuReddy's versioned policy.
Accepted deprecated or weak-classical transforms are separate hygiene/downgrade evidence; an
encryption transform alone does not establish HNDL exposure. ADDKE or ML-KEM selection is outside
the pre-PQC release and is not proof of a completed KEM exchange. UDP silence, filtered traffic,
malformed data, and unsupported local capabilities remain explicit non-positive/unknown states.

Every reviewed profile is tied to the versioned algorithm catalog and emits per-row coverage:
planned, attempted, accepted, explicitly rejected, unknown, or `not_tested`. The bounded default
profile claims only its declared covering set. The legacy profile must cover the catalog entries
selected by the reviewed IKE policy for Historic, weak-classical, and HNDL-relevant assessment;
any catalog row outside the scheduled budget remains explicit `not_tested`. Custom caller tuples
may be added only through the same strict catalog, binding, budget, and coverage path; they do not
create an unbounded Cartesian sweep.

### 5.3 Response binding requirements

Positive evidence requires one selected transform subset from exactly one offered proposal, with
returned transform attributes preserved unchanged, including key length. The parser/binder must
reject or classify as non-positive:

- wrong source address or destination port;
- wrong IKE version, exchange type, response flag, IKEv1 cookie or IKEv2 SPI, or message ID;
- a response that cannot be bound to the unique request initiator cookie/SPI, exchange, message ID,
  source, retry state, and offered-proposal fingerprint; IKEv2 does not echo the initiator nonce
  in `IKE_SA_INIT`, so nonce equality is never used as a binding requirement;
- duplicate, replayed, truncated, oversized, or length-inconsistent datagrams;
- payload chains that exceed declared bounds or contain unknown critical payloads;
- selected transforms not present in the offered proposal set;
- forged SA selections and incomplete intermediate exchanges.

The transport and binder also enforce these typed paths:

- QuReddy permits at most one protocol-conformant `COOKIE` retry per probe; the retry is bound to
  the original probe and echoes the cookie unchanged;
- `INVALID_KE_PAYLOAD` names a preferred key exchange method and creates a separately identified
  retry whose response is evidence only for that second probe;
- `NO_PROPOSAL_CHOSEN` rejects only the exact offered batch;
- IKEv1 NAT-T Vendor-ID negotiation on UDP/500 remains separate from IKEv2 NAT detection;
- UDP/4500 requires the four-octet non-ESP marker; and
- duplicate or retransmitted datagrams cannot create duplicate observations.

Pre-PQC retry evidence records the configured retry policy, bounded attempt count, elapsed timing
metadata, and the terminal typed outcome. Exhausting the budget leaves affected rows incomplete
or unknown. Timing and silence never identify a vendor or prove an algorithm unsupported. Full
retransmission/backoff fingerprint parity remains #563.

Vendor-ID payloads are recognized only where the pinned protocol contract requires it, such as
IKEv1 NAT-T. Public evidence may retain a bounded length, SHA-256 digest, observation reference,
and catalog/provenance version. It never retains raw Vendor-ID bytes or assigns a vendor name from
an unreviewed fingerprint database. Broader fingerprint interpretation remains #563.

The direct predicate reproduction recorded in #598 demonstrates a false-`PROTECTED` path; no IKE
fixture or implemented IKE CLI exists yet. That defect is a release blocker until a
failing-before-fix regression test covers the shared evaluator and the installed real CLI keeps
forged, partial, and unauthenticated IKE evidence non-`PROTECTED` in every output format.

## 6. CLI contract

### 6.1 Command

```console
qureddy scan ike TARGET[:PORT]
```

Examples:

```console
# Syntax examples only. The reserved example addresses are not acceptance targets.
# Probe both protocol families with the default observation profile.
qureddy scan ike vpn.example.com

# Explicit port and IPv6 literal.
qureddy scan ike 203.0.113.10:500 --port 500
qureddy scan ike '[2001:db8::10]:4500' --port 4500

# Request both protocol families and verbose packet-stage diagnostics.
qureddy scan ike vpn.example.com --ike-version all --v1-mode all -vvv

# Machine-readable output and a complete one-scan bundle.
qureddy scan ike vpn.example.com --format json
qureddy scan ike vpn.example.com --format jsonl
qureddy scan ike vpn.example.com --format cbom
qureddy scan ike vpn.example.com --output-dir run/
```

The exact option spelling must follow the existing Typer option conventions; the
implementation must not introduce aliases that collide with global verbosity or
output options. `--output-dir` writes the same bundle contract used by TLS/SSH.

The 0.13 pre-PQC release exposes no completion-mode CLI option and no `pqc` profile. Those
additions belong to the 0.14 work in #555 and #562 and cannot be implied by `--profile`,
`--ike-version`, or a selected ADDKE/ML-KEM transform. No alternate version spellings are
accepted because aliases would create incompatible scripts and documentation.

### 6.2 Proposed options

| Option | Default | Contract |
|---|---:|---|
| `--ike-version` | `all` | `1`, `2`, or `all`; `all` probes both and never upgrades unknown to secure |
| `--v1-mode` | `all` | `main`, `aggressive`, or `all` (only with version `1`/`all`) |
| `--profile` | `default` | pre-PQC reviewed covering profile; not a Cartesian sweep and no PQ selection |
| `--port` | `500`/profile | UDP 500 or 4500 only for the first release |
| `--nat-t` | `auto` | `auto`, `off`, or `force`; no alternate vocabulary |
| `--timeout` | existing default | per-datagram timeout, bounded by existing limits |
| `--retries` | existing default | bounded retransmission, no unbounded loop |
| `--retry-delay` | existing default | bounded delay between attempts |
| `--max-probes` / `--batch-size` | profile defaults | explicit work budget and scheduling bounds |
| `--deadline` | existing default | whole-scan deadline |
| `--format` | `rich` | `rich`, `json`, `jsonl`, `cbom` |
| `--output` | none | one selected output file |
| `--output-dir` | none | all supported projections from one result |
| `-v/-vv/-vvv` | 0 | diagnostics only; never changes evidence |
| `--log` | none | structured diagnostic log, separate from machine stdout |

No CLI option accepts a PSK, XAUTH username/password, `HASH_R`, or a tunnel
configuration. Those features are explicitly rejected as out of scope.

The planned 0.14 CLI adds `--profile pqc` and
`--completion selection|pre-auth|required-pre-auth` only after #555/#562 acceptance. These
options are not placeholders in the 0.13 parser, help output, configuration model, or provider
protocol.

### 6.3 Exit codes

Use existing exit-code semantics:

| Outcome | Exit |
|---|---:|
| At least one valid observation or explicit typed target outcome | existing success/target result contract |
| Target unreachable, filtered, malformed, or protocol failure | existing target-failure code |
| Local capability/provider unavailable | existing local-dependency code |
| Invalid target or option | existing usage code |
| Unhandled bug | existing internal-error code |

The exact numeric values remain owned by `cli/_errors.py`; help text must derive
from those constants rather than duplicate numbers.

## 7. Evidence and HNDL evaluation

### 7.1 Policy inputs

The shared evaluator consumes neutral facts:

```python
IKEPolicyFacts(
    version=IKEVersion.V2,
    outcome=NegotiationOutcome.ACCEPTED,
    evidence_level=EvidenceLevel.SELECTED,
    classical_algorithms=("AES-CBC", "HMAC-SHA1", "MODP-1536"),
    pq_algorithms=(),
    downgrade_observed=True,
    nat_t=IKENatT.AUTO,
    authentication_status="unknown",
)
```

The evaluator produces the existing `ScanInterpretation` shape, extended only
with protocol-neutral evidence references where necessary:

```text
effective readiness
headline
recommended action
hndl_exposure
hygiene_status
axes:
  pqc_support
  key_exchange
  downgrade_resistance
  authentication
  protocol_hygiene
reason_codes
evidence_refs
policy_id / policy_version
```

### 7.1.1 Scoped HNDL assessment

The canonical result carries HNDL scope explicitly. Renderers and CBOM consume
this object; they must not flatten it into a renderer-specific global verdict.

```python
class HndlScope(str, Enum):
    IKE_SA_KEY_ESTABLISHMENT = "ike_sa_key_establishment"
    OVERALL_IPSEC = "overall_ipsec"

class HndlDisposition(str, Enum):
    AT_RISK = "at_risk"
    UNKNOWN = "unknown"
    NOT_TESTED = "not_tested"

@dataclass(frozen=True, slots=True)
class ScopedHndlAssessment:
    scope: HndlScope
    disposition: HndlDisposition
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
```

The pre-PQC unauthenticated release may report
`IKE_SA_KEY_ESTABLISHMENT / AT_RISK` for an accepted classical tuple, while it
must report `OVERALL_IPSEC / UNKNOWN`. The scan has not observed IKE_AUTH,
Child-SA, ESP/AH, traffic selectors, or PFS behavior. If the legacy global
`hndl_exposure` field remains for compatibility, it stays `unknown` here and is
not authoritative. Future authenticated or Child-SA evidence requires a
separate contract revision.

### 7.1.2 Semantic-signal naming contract

IKE findings use the existing protocol-neutral key-establishment suffix contract. The
`finding_type` and `readiness` pair is structural input to the shared evaluator:

| IKE finding type | Readiness | Neutral signal |
|---|---|---|
| `ike.kex.classical` | `quantum_vulnerable` | `kex.classical` |
| `ike.kex.hybrid` | `transitional_hybrid` | `kex.hybrid_pqc` |
| `ike.kex.pure_pq` | `quantum_safe` | `kex.pure_pqc` |

The evaluator must require both members of the pair. A bare readiness value, a generic
`ike.proposal.selected` identifier, an unknown suffix, or a mismatched pair produces an
evaluation gap and never a favorable signal. Rule identifiers may give a more specific reason,
but they do not replace the canonical finding-type suffix.

These signals classify only the evidenced IKE key-establishment axis. The IKE scope guard keeps
the legacy global `hndl_exposure` field `unknown`; no IKE-only semantic signal may produce global
`protected` or `protected_defeasible`. Issue #598 owns enforcement and regression tests for this
contract before #554 emits IKE findings.

### 7.2 Required semantic rules

1. A classical-only accepted proposal produces scoped IKE-SA HNDL `AT_RISK`
   with named algorithms and evidence references. Overall unauthenticated IPsec
   posture remains `UNKNOWN`; `PROTECTED_DEFEASIBLE` is not valid for this scope.
2. IKEv1 discovery never implies PQ support.
3. Capability notifications and proposal selection never imply completed protection.
4. `completed` is not part of the observation release. Protected
   `IKE_INTERMEDIATE`/ADDKE completion requires the separate #562
   decision and provider/security/conformance gates.
5. No response, filtering, malformed packets, and unsupported local capability
   produce `UNKNOWN`/`NOT_TESTABLE`, not a favorable posture.
6. A corroborator disagreement is preserved as evidence and cannot silently
   improve the posture.

The pre-PQC provider surface is exact:

```python
class IKEKeyShareHandle(Protocol):
    """Opaque provider-owned handle; never serialized, logged, or inspected."""

@dataclass(frozen=True, slots=True)
class IKEInitiatorKeyShare:
    method_id: int
    public_value: bytes
    handle: IKEKeyShareHandle = field(repr=False)

class IKEObservationProvider(Protocol):
    dependency: CryptoProviderDependency
    supported_method_ids: frozenset[int]

    def create_initiator_key_share(self, method_id: int) -> IKEInitiatorKeyShare: ...
    def dispose(self, handle: IKEKeyShareHandle) -> None: ...
```

`public_value` is the catalog-bounded canonical KE public value passed to the codec; it is not
retained in public evidence. `create_initiator_key_share` uses the locked production PyCA provider
and returns a typed local-provider failure for unsupported or broken capabilities. `dispose` is
idempotent and runs in `finally` on success, timeout, malformed response, cancellation, and
failure. The provider records its backend and supported method IDs through the single
`RuntimeDependency` path owned by #473.

No other public callable belongs to `IKEObservationProvider` through 0.13. Architecture tests
must compare the callable surface to
`{"create_initiator_key_share", "dispose"}` and reject shared-secret derivation, responder-payload
consumption, IKE KDFs, encryption/decryption, integrity, `derive`, `protect`, `verify`, transcript
completion, authentication, or Child-SA methods. Those completion-only methods require the
separate #562 contract change. ML-KEM/ADDKE capability and completion types remain in the 0.14
design until #555/#562 implement and verify them; they are not selectable pre-PQC provider
methods, profiles, or CLI options.

### 7.3 Output parity

The same observation and interpretation must appear consistently in:

- Rich: concise operator/CISO summary plus protocol details;
- JSON: canonical document with `scan`, `observations`, `findings`, and
  `interpretation`;
- JSONL: one deterministic finding/evidence record per line;
- CBOM: only validated positive cryptographic observations, with tool provenance
  and protocol metadata; no direct raw `ike-scan` ingestion.

## 8. External validator contract

### 8.1 EnXemble role

EnXemble may run QuReddy as the primary tool and `ike-scan` as an optional independent
validator/corroborator. The descriptor schema, image reference, artifact names, and validator
state model belong exclusively to EnXemble issue #51; this ADR defines no example descriptor.
The validator checks native IKEv1 claims, never decides PQ readiness, never writes CBOM, and
must distinguish `pass`, `conflict`, `unavailable`, and `no_result`. Absence of the validator is
not a QuReddy 0.12/0.13 release blocker.

### 8.2 Provenance and disagreement

```python
ValidatorObservation(
    validator="ike-scan",
    version="1.9.5",
    role="corroborating",
    target="vpn.example.com:500",
    status="pass|conflict|unavailable|no_result",
    parsed_facts={...},
    evidence_refs=(...),
)
```

The validator result is attached to provenance/evidence. It cannot replace the native
`IKEProposalObservation`, change the authoritative collector role, or upgrade
`hndl_exposure` by itself.

## 9. File-level implementation plan

### 9.1 QuReddy files to change

The single authoritative file/component map is in section 16.1 below. This section
intentionally does not repeat it; child issues own their exact file deltas. No child may
introduce the superseded `packet.py`/`probe.py`/`parser.py`/`bind.py`/`classify.py` graph or
duplicate the generic registry, evaluator, renderer, or CBOM path.

### 9.2 Tests and fixtures to add

| File | Coverage |
|---|---|
| `tests/test_ike_models.py` | strict model validation, ports, enums, immutability |
| `tests/test_ike_targets.py` | hostname/IP/IPv6/port/control-character cases |
| `tests/test_ike_packet.py` | length, payload-chain, critical-payload, truncation cases |
| `tests/test_ike_parser.py` | parser-negative byte corpus and notify classification; positive negotiation is live-only |
| `tests/test_ike_binding.py` | wrong SPI/source/version/message ID/proposal/duplicates; no echoed-nonce assumption |
| `tests/test_ike_probe.py` | timeout/retry/NAT-T/filtered behavior with an authorized live UDP peer |
| `tests/test_ike_scanner.py` | canonical `CollectionResult` and typed failures |
| `tests/test_ike_policy.py` | evidence ladder and HNDL semantics |
| `tests/test_ike_cli.py` | real installed CLI parsing, help, exit codes, output flags |
| `tests/test_ike_output.py` | Rich/JSON/JSONL parity and output-dir single acquisition |
| `tests/test_ike_cbom.py` | CycloneDX validation and consumer compatibility |
| `tests/fixtures/ike/*.bin` | malformed/forged parser-safety inputs only; never positive negotiation evidence |
| `tests/live/test_live_ike.py` | opt-in strongSwan/veepin lab interoperability |
| `tests/fuzz/fuzz_ike_packet.py` | parser non-crash and bounded-resource properties |

These five must fail before the section 4.1 contract is implemented. Each is a
pure model or projection test needing no socket, so none is blocked on a peer:

| Test | Asserts | Fails today because |
|---|---|---|
| `test_ike_models.py::test_attempt_sequence_is_lossless` | an `INVALID_KE_PAYLOAD` first leg and its retry survive as two `IKEAttemptEvidence` with distinct `ordinal`, `source.port`, and `responder_spi`, the retry carrying `role=invalid_ke_retry` and `parent_ordinal=1` | `IKEAttemptEvidence` does not exist; `attempts: int` cannot hold two source ports |
| `test_ike_models.py::test_retransmission_creates_no_second_observation` | a `role=retransmission` attempt appends to `attempts` and yields exactly one `IKEProposalObservation` | no attempt role exists to distinguish a retry from a retransmission |
| `test_ike_models.py::test_notifications_are_ordered_and_repeatable` | two `NAT_DETECTION_SOURCE_IP` plus one `NAT_DETECTION_DESTINATION_IP` round-trip in received order, and a `COOKIE` notification stores `data_length` and `data_sha256` with `data_hex` unset and `redacted=True` | `notify_type: int \| None` holds one value and has no redaction boundary |
| `test_ike_models.py::test_nat_states_are_distinguishable` | `requested=force` with no vendor ID observed, versus vendor ID observed with `translation=none_detected`, versus `port_float=unavailable`, are three distinct serializations | `nat_t: bool` collapses all three |
| `test_ike_policy.py::test_not_tested_names_its_row` | a receipt whose `entries` contain ML-KEM-512 / ID 35 with `state=not_tested` reports `not_tested == 1`, exposes `proposal_id`, and produces **no** `IKEProposalObservation` | `not_tested: int` is an integer with no row identity |

A sixth is a guard rather than a feature: `test_ike_models.py::test_totals_are_derived_from_entries`
asserts a `CoverageReceipt` whose integer totals disagree with its `entries` is
rejected at construction, so a total can never be authored independently.

### 9.3 EnXemble files (separate repository/follow-up)

Do not modify EnXemble in the QuReddy implementation PR. The follow-up changes
belong in the EnXemble repository:

```text
tools/qureddy-ike/qureddy-ike.yaml       descriptor
src/enxemble/...                         validator role/status model
tests/...                                descriptor and three-state validator tests
docs/reference/descriptor-schema.md      validator corroboration contract
docs/explanation/architecture.md         primary run/validator flow
```

The EnXemble issue must depend on the QuReddy release that first ships `scan ike`.

## 10. Test and pressure-test plan

All implementation work follows the repository ten-step loop:

1. Inventory the issue, current tree, local guidance, skills, and overlapping work.
2. Steelman the problem and the smallest defensible slice; record the rejected alternative.
3. Reproduce current behavior in an isolated `/tmp` workstream before patching.
4. Pressure-test malformed input, compatibility, regressions, and the named falsifier.
5. Implement the smallest seam-preserving change.
6. Add regression tests that fail before and pass after the change.
7. Run locked unit, quality, documentation, supply-chain, and release gates.
8. Perform architecture and anti-pattern review, including duplication and boundaries.
9. Record issue, commit, review, and artifact evidence.
10. Verify built wheel/container and real-lab behavior separately; unrun items are `NOT RUN`.

### 10.1 Required lab matrix

| Fixture/peer | Expected proof |
|---|---|
| Classical IKEv1 responder | version/mode/transform evidence; HNDL risk named |
| IKEv1 Aggressive responder | discovery only; no PSK/hash capture |
| Classical IKEv2 responder | classical proposal selected; no PQ claim |
| PQ-capable strongSwan/veepin responder | 0.14.0 parity work; not a 0.13.0 release gate |
| `NO_PROPOSAL_CHOSEN` | typed notify, no success inference |
| COOKIE retry | bounded retry and correct correlation |
| filtered UDP | `filtered`/unknown, not secure |
| forged/wrong-SPI response | non-positive; never `PROTECTED` |
| malformed/truncated payload | typed parse failure; process remains alive |
| EnXemble + `ike-scan` disagreement | explicit corroborator conflict |

### 10.2 Real CLI commands

Issue #570 must publish `docs/lab/ike-peer-matrix.md` before these commands become executable.
Each matrix row has one stable ID and records the peer implementation/version, immutable image or
package digest, configuration digest, host, UDP port, IKE version/mode, NAT-T state, exact offered
and expected selected `qureddy.ike.proposal.v2` objects, expected outcome/exit, responder-log
command, and expected authoritative log fields. Missing cells are `NOT RUN` with release impact;
they are never inferred from another row.

Issue #561 must run the built wheel and production image against the same named rows. The evidence
bundle records the source revision, wheel SHA-256, installed distribution/version, OCI manifest
digest, image-reported version, command, exit code, stdout, stderr, output digests, and the matching
responder-log excerpt digest. The responder log corroborates the exchange but never replaces
QuReddy's bound network evidence.

The acceptance command shape is:

```console
export QUREDDY_WHEEL="dist/<built-wheel>.whl"
export QUREDDY_IMAGE="ghcr.io/breachsafe/qureddy@sha256:<manifest-digest>"
export QUREDDY_IKE_V1_MAIN_HOST="<host-from-#570-row>"
export QUREDDY_IKE_V1_AGGRESSIVE_HOST="<host-from-#570-row>"
export QUREDDY_IKE_V2_HOST="<host-from-#570-row>"
export QUREDDY_IKE_LAB_NETWORK="<network-from-#570>"

shasum -a 256 "$QUREDDY_WHEEL"
uv run --isolated --no-project --with "$QUREDDY_WHEEL" qureddy --version
docker image inspect "$QUREDDY_IMAGE" --format '{{json .RepoDigests}}'
docker run --rm "$QUREDDY_IMAGE" --version

uv run --isolated --no-project --with "$QUREDDY_WHEEL" qureddy scan ike \
  "$QUREDDY_IKE_V1_MAIN_HOST" --port 500 --ike-version 1 --v1-mode main -vvv
uv run --isolated --no-project --with "$QUREDDY_WHEEL" qureddy scan ike \
  "$QUREDDY_IKE_V1_AGGRESSIVE_HOST" \
  --port 500 --ike-version 1 --v1-mode aggressive --format json --output v1-aggressive.json
uv run --isolated --no-project --with "$QUREDDY_WHEEL" qureddy scan ike \
  "$QUREDDY_IKE_V2_HOST" \
  --port 500 --ike-version 2 --format jsonl --output v2.jsonl
uv run --isolated --no-project --with "$QUREDDY_WHEEL" qureddy scan ike \
  "$QUREDDY_IKE_V2_HOST" \
  --port 4500 --ike-version 2 --nat-t force --format cbom --output v2-natt.cdx.json
uv run --isolated --no-project --with "$QUREDDY_WHEEL" qureddy scan ike \
  "$QUREDDY_IKE_V2_HOST" --port 500 --ike-version 2 --output-dir run/

docker run --rm --network "$QUREDDY_IKE_LAB_NETWORK" "$QUREDDY_IMAGE" \
  scan ike "$QUREDDY_IKE_V2_HOST" --port 500 --ike-version 2 -vvv
```

The matrix supplies expected tuples and responder log commands; placeholders above are not
executable evidence. A checkout or editable install does not satisfy acceptance. Reserved
documentation addresses and silent public endpoints do not qualify.

## 11. Security and safety controls

- Use `subprocess` nowhere in native IKE collection; use a bounded UDP socket
  with explicit address and timeout handling.
- Never accept a response solely because it has a parseable SA payload.
- Bind response to the IKEv1 initiator cookie or IKEv2 initiator SPI, retry state, exact offered
  tuple, source, exchange, flags, and message ID before classifying any selected algorithm. Do not require an echoed
  initiator nonce that the protocol does not provide.
- Cap datagram length, payload count, recursion, retries, and retained raw bytes.
- Never log PSKs, XAUTH credentials, authentication hashes, or full sensitive
  payloads. `-vvv` exposes packet-stage metadata and digests only.
- Run as the existing unprivileged container user; UDP 500/4500 does not require
  raw sockets for the first probe.
- Treat `ike-scan` as an optional executable with version/provenance capture and
  unavailable status when absent.
- Keep licensing and platform review separate before distributing `ike-scan` in
  any image.

## 12. Alternatives and trade-offs

| Option | Strongest case | Kill-shot | Decision |
|---|---|---|---|
| Native Python scanner + EnXemble `ike-scan` validator | One canonical result, precise HNDL semantics, independent IKEv1 corroboration | QuReddy owns parser and protocol maintenance | **Selected** |
| `ike-scan` as QuReddy primary | Mature IKEv1 discovery and transform output | Experimental/configuration-limited IKEv2; no modern PQ authority; exit-0 ambiguity | Rejected as primary |
| Direct `ike-scan` to CBOM | Fast inventory demo | Second evidence truth, no shared Rich/JSON/JSONL contract | Rejected |
| Go/Rust sidecar as primary | Strong packet libraries and future provider options | Adds runtime/package/image boundary before evidence contract is stable | Deferred |
| Fork `ike-scan` | Reuse mature C implementation | GPL fork ownership plus still-missing modern IKEv2/PQ work | Rejected |

The architecture contract is accepted. Implementation readiness remains blocked until the
forged-response guard, lifecycle prerequisites, pinned real lab, installed wheel, production
image, and acceptance criteria below are demonstrated. Design acceptance is not execution
evidence.

## 13. Acceptance criteria

- [ ] Existing collector lifecycle is live for the IKE CLI; no direct scanner
      bypass remains.
- [ ] Target/request models are strict, immutable, and lossless for UDP/500/4500.
- [ ] Parser-negative fixtures parse deterministically; every positive negotiation
      and readiness claim comes from a live authorized IPsec peer.
- [ ] Source/port/IKEv1-cookie/IKEv2-SPI/version/exchange/flags/message-ID/retry-state/proposal
      binding rejects forged and replayed responses; accepted transforms are a subset of one
      exact offered proposal and returned attributes remain unchanged.
- [ ] `COOKIE`, `INVALID_KE_PAYLOAD`, and `NO_PROPOSAL_CHOSEN` follow their typed retry or
      exact-batch semantics without widening a support or rejection claim.
- [ ] IKEv1 Vendor-ID NAT-T negotiation, IKEv2 NAT detection, and UDP/4500 non-ESP framing are
      exercised independently against authorized live peers.
- [ ] Accepted, rejected, unknown, and not-tested states are distinct; first release
      never emits `PROTECTED` for unauthenticated IKE evidence.
- [ ] IKEv1 evidence never becomes PQ support.
- [ ] A bound IKEv1 result emits a Historic finding. Bound Aggressive Mode emits identity exposure
      unless public-key-encryption authentication protects identity. When PSK authentication is
      selected, it emits the separate offline-guessing exposure finding. That credential/classical
      finding remains separate from the HNDL finding, which is driven by the selected key-exchange
      tuple. Identity and authentication hash material never enter public output.
- [ ] Every profile emits catalog-linked planned/attempted/accepted/rejected/unknown/not-tested
      coverage; bounded or unscheduled legacy rows remain explicit rather than disappearing.
- [ ] Pre-PQC retry evidence preserves bounded attempts, configured policy, timing metadata, and
      incomplete coverage without inferring vendor identity or unsupported algorithms.
- [ ] Vendor-ID evidence is digest-only and provenance-linked; raw bytes and unreviewed vendor
      attribution never cross the public boundary.
- [ ] No response/filtering/malformed/unsupported states remain explicit.
- [ ] Rich, JSON, JSONL, CBOM, and `--output-dir` have evidence-ID and interpretation parity
      from one acquisition and one `ScanResult`; CBOM contains no raw packet, nonce, KE,
      identity, PSK, authentication-hash, or secret material.
- [ ] Built wheel and container commands pass the lab matrix with recorded output.
- [ ] Parser fuzzing, mutation/negative fixtures, architecture-boundary checks, and
      real CLI tests pass.
- [ ] If the optional EnXemble `ike-scan` validator is present, it reports
      `pass`, `conflict`, `unavailable`, and `no_result` correctly; exit-0/no-handshake is
      `no_result`, not `pass`.
      Validator absence does not block 0.12.0 or 0.13.0.
- [ ] TLS and SSH golden outputs, exit codes, package, and image remain unchanged.
- [ ] Documentation, changelog, provenance, license, and release gates pass.

## 14. Rollout and compatibility

The first release adds `scan ike` without changing TLS/SSH defaults. Existing
`ScanResult`, JSON, JSONL, and CBOM fields remain backward compatible; new IKE
fields are additive and namespaced. If a consumer does not understand IKE, it
must preserve the observation as an unknown protocol rather than discard it.

The feature is initially opt-in through the new command. No existing scan runs
invoke UDP/500 or UDP/4500 implicitly. `ike-scan` is never installed as a
transitive package dependency.

## 15. Open decisions

The CycloneDX 1.7 mapping is closed by section 7.3 and #554:
`protocolProperties.type: "ike"` for the endpoint protocol component, linked algorithm assets for
ENCR/PRF/INTEG/KE/ADDKE, and namespaced properties for ADDKE transform types 6 through 12.

One operational decision remains: which real FortiGate/strongSwan interoperability endpoints can
be used under the approved test authorization? Provider selection, IKEv1/IKEv2 sequencing,
validator ownership, and completion scope are closed by this ADR and its child issues.

## 16. Implementation handoff and ownership

The plan of record is this ADR and the assigned child issues from `0.10.0` through `0.14.0`.
Issue #546 tracks delivery and links this contract; it does not define a parallel model or CLI.

### 16.1 File and component map

```text
CLI -> target parser -> CollectorRegistry -> NativeIKECollector -> IKEScanner
                                                            |
                           +----------------+---------------+----------------+
                           v                v                                v
                    UDP transport       IKE catalog                       provider
                           |                |                                |
                           +--------> codec/binding <-----------------------+
                                          |
                                          v
                                bound IKE observation
                                          |
                                          +--> coverage receipt
                                          +--> neutral policy facts
                                          |
                                          v
                                    shared evaluator
                                          |
                                          v
                           one immutable ScanResult (IKEScanner)
                                          |
                                          v
                           CollectionResult.scan_result (same object)
                               /          |          \
                            Rich        JSON/JSONL     CBOM
```

The source tree is divided by ownership:

```text
src/qureddy/cli/ike.py                       CLI only
src/qureddy/core/contracts.py                neutral capability/provenance seams
src/qureddy/core/models.py                   additive public result types
src/qureddy/core/targets.py                  lossless IKE target parsing
src/qureddy/core/registry.py                 deterministic selection
src/qureddy/collectors/native.py             source-to-scanner adapter
src/qureddy/scanners/ike/models.py           private wire/request types
src/qureddy/scanners/ike/catalog.py          pinned IANA IDs and profiles
src/qureddy/scanners/ike/codec.py            bounded encode/parse/bind
src/qureddy/scanners/ike/transport.py        UDP 500/4500 and NAT-T
src/qureddy/scanners/ike/sweep.py            proposal scheduling/coverage
src/qureddy/scanners/ike/provider.py         observation-scoped provider port
src/qureddy/scanners/ike/findings.py         observation-to-neutral-facts mapping
src/qureddy/scanners/ike/scanner.py          orchestration only
src/qureddy/output/cbom_ike.py               public-model CBOM projection only
```

No IKE parser, transport, provider, or external-validator logic may be added to
CLI, renderer, or generic output modules. `ike-scan` remains an EnXemble-side
validator/oracle and never enters this tree as a runtime dependency.

### 16.2 Single-owner data model

```text
IKEScanConfig                 CLI/profile defaults; one owner
IKEProbeRequest               one concrete wire attempt; private
ParsedIKEResponse             syntactically parsed, still untrusted; private
ValidatedIKEResponse          request-bound response; private constructor
IKETransformAttribute         exact typed TV/TLV attribute; public evidence
IKETransformObservation       exact ordered wire transform; public evidence
IKEEndpoint                   ip/port pair; public, shared by attempts
IKEAttemptEvidence            one datagram exchange; public, never collapsed
IKENotificationObservation    one notification, ordered as received; public
IKENatObservation             NAT-T evidence spanning IKEv1 NAT-D and IKEv2 notify
IKEProposalObservation        public positive/negative observation; one output input
CoverageEntry                 one catalog/profile row; the only home of not_tested
CoverageReceipt               derived totals over CoverageEntry; never authored alone
ScanResult                    constructed once by IKEScanner; renderer input
CollectionResult              collector wrapper carrying the same ScanResult
ValidatorObservation          EnXemble corroborator provenance, separate from evidence
```

Do not create parallel `IKEVersion`, `IKEExchange`, `EvidenceLevel`, transport,
coverage, dependency, or completion types. Generic concepts have one neutral
owner; wire-specific concepts remain private to `scanners/ike`.

### 16.3 Per-issue working agreement

For every child issue:

- **Codex writes the production code and owns the implementation diff.**
- **Claude writes and maintains the tests**, including real lab scripts and
  acceptance evidence, without weakening assertions or hiding failures.
- **Codex monitors bugs on every check-in**: review the diff, run the relevant
  anti-pattern categories, inspect test integrity, and record regressions before
  moving to the next slice.
- Neither agent may claim a gate passed without the command, version, exit code,
  and artifact being recorded.
- No mocks or fake peers satisfy production-path acceptance. Deterministic byte
  fixtures are limited to parser-negative and fuzz safety cases.
- A child issue cannot close while a required gate is `NOT RUN`.

### 16.4 Milestone exit contract

```text
0.10.0  contracts, catalog, identity, Phase-0 prerequisites
0.11.0  real IKEv1/IKEv2 classical observations and strict binding
0.12.0  canonical findings, all outputs, coverage; optional EnXemble provenance
0.13.0  pre-PQC package/image/docs/release verification
0.14.0  IKE PQC and Discovery Parity: #555, #562, #563
```

Each milestone exit requires the real installed CLI and, where applicable, the
built container against the local IPsec harness. Public endpoint silence is not
an acceptance result. Existing TLS/SSH output compatibility remains a gate for
every milestone.

## 17. Implementation quality bar

The architecture is not permission to lower the repository's coding standards.
Every production slice must meet the following bar before review:

- Python 3.14+, locked environment, strict typing, formatter/linter clean, and
  repository quality gates run with recorded exit codes;
- files target 300 lines or fewer and must not exceed 400 without an issue-backed
  exception; functions target 30 lines or fewer and must not exceed 50;
- no `Any`, broad exception swallowing, mutable global registries, hidden retries,
  duplicated defaults, protocol-specific renderer branches, or dead/TODO code;
- no shell invocation for native IKE collection; all network work is bounded and
  cancellable;
- no monkeypatching of production wiring to make tests pass;
- every new test must have a real-path counterpart where the feature touches the
  CLI, provider, container, or network;
- positive negotiation, downgrade, PQ, and interoperability evidence is live-only
  from the authorized local IPsec harness; byte fixtures and fuzz inputs prove
  parser safety only;
- Codex reviews its own diff for architecture and anti-pattern violations at each
  check-in; Claude owns the test implementation and evidence record;
- a failed, skipped, unavailable, partial, or unrun gate remains explicit and
  cannot be converted into a clean or protected result.

### 17.1 References

The normative claims in this ADR are grounded in the corpus vendored by the private
`paul007ex/breachsafe-common` knowledge repository, whose local checkout is named
`breachsafe-standards`. Repository-qualified paths below are not QuReddy paths:

| Claim | Vendored source and line |
|---|---|
| IKEv2 responder selects one offered suite | `breachsafe-common:standards/rfc/rfc7296/rfc7296.txt:1970` |
| IKEv1 is Historic | `breachsafe-common:standards/rfc/rfc9395/rfc9395.txt:18` |
| Aggressive identity behavior depends on authentication method | `breachsafe-common:standards/rfc/rfc2409/rfc2409.txt:309-314` |
| Aggressive Mode with PSK returns responder identity and `HASH_R` before initiator authentication | `breachsafe-common:standards/rfc/rfc2409/rfc2409.txt:514-540,865-871` |
| NAT-T Vendor-ID appears in the first two Phase 1 messages | `breachsafe-common:standards/rfc/rfc3947/rfc3947.txt:178-181` |
| IKEv1 NAT-D detects address/port translation | `breachsafe-common:standards/rfc/rfc3947/rfc3947.txt:192-216` |
| IKEv2 uses `NAT_DETECTION_SOURCE_IP` and `NAT_DETECTION_DESTINATION_IP` | `breachsafe-common:standards/rfc/rfc7296/rfc7296.txt:3560-3614` |
| UDP/4500 uses the non-ESP marker | `breachsafe-common:standards/rfc/rfc3947/rfc3947.txt:323-328` |
| IKE_INTERMEDIATE exchange definition and protection | `breachsafe-common:standards/rfc/rfc9242/rfc9242.txt:190-249,524` |
| ADDKE1 through ADDKE7 use transform types 6 through 12 | `breachsafe-common:standards/rfc/rfc9370/rfc9370.txt:329-338` |
| RFC 8247 `MUST NOT` ENCR/PRF/INTEG/KE rows | `breachsafe-common:standards/rfc/rfc8247/rfc8247.txt:294-296,377,430,518` |
| IKEv2 `INVALID_KE_PAYLOAD` retry semantics | `breachsafe-common:standards/rfc/rfc7296/rfc7296.txt:662-675` |
| IKEv2 `NO_PROPOSAL_CHOSEN` rejects the offered proposals | `breachsafe-common:standards/rfc/rfc7296/rfc7296.txt:1973-1976,5675-5681` |
| IKEv2 `COOKIE` retry echoes unchanged data and otherwise unchanged payloads | `breachsafe-common:standards/rfc/rfc7296/rfc7296.txt:1799-1807` |

The accepted corpus snapshot is `paul007ex/breachsafe-common` revision
`77f9e5a66dd168634d410129904cd946eacf7411`. Its `standards/rfc/README.md` SHA-256 is
`4ba1641e1880eef42a0294e879033d01d694ebea7c5e83415a2b3dacd863a05c`; the pinned IKEv2 registry
reports `updated=2026-07-16`. Verification from this checkout uses
`.agents/skills/breachsafe-ipsec-conformance/scripts/verify_corpus.sh` and reports 144 files,
integrity PASS, registry closure 95/95, and ML-KEM draft revision `-09`. Counts in explanatory
skills or historical comments are non-authoritative when they differ from this verifier output.

- [RFC 7296 — Internet Key Exchange Protocol Version 2 (IKEv2)](https://www.rfc-editor.org/info/rfc7296)
- [RFC 2409 — The Internet Key Exchange (IKE)](https://www.rfc-editor.org/info/rfc2409)
- [RFC 3947 — Negotiation of NAT-Traversal in the IKE](https://www.rfc-editor.org/info/rfc3947)
- [RFC 9395 — IKEv1 Historic Status](https://www.rfc-editor.org/info/rfc9395)
- [RFC 9242 — IKE_INTERMEDIATE](https://www.rfc-editor.org/info/rfc9242)
- [RFC 9370 — Additional Diffie-Hellman exchanges](https://www.rfc-editor.org/info/rfc9370)
- [ike-scan project](https://github.com/royhills/ike-scan)
- [EnXemble descriptor architecture](https://github.com/BreachSAFE/enxemble/blob/docs/readme-tuneup/README.md)
