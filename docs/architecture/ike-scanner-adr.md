<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR: IKE HNDL evidence scanner

[![Architecture decision](https://img.shields.io/badge/QuReddy-architecture%20decision-8250df?style=flat-square)](https://github.com/BreachSAFE/qureddy/blob/main/docs/architecture/ike-scanner-adr.md)

**Tag:** `[546]`
**Status:** Proposed for maintainer review
**Scope:** QuReddy native IKE observation and canonical output integration
**Issue:** [#546](https://github.com/BreachSAFE/qureddy/issues/546)

This document mirrors the normative contract in #546. If this file and #546 differ,
`#546` controls until this document is corrected. Earlier draft issues are historical
material only and are not authorities for implementation.

## Contents

1. [Decision summary](#1-decision-summary)
2. [Problem and non-goals](#2-problem-and-non-goals)
3. [Architecture](#3-architecture)
4. [Canonical data contract](#4-canonical-data-contract)
5. [IKE protocol contract](#5-ike-protocol-contract)
6. [CLI contract](#6-cli-contract)
7. [Evidence and HNDL evaluation](#7-evidence-and-hndl-evaluation)
8. [External validator contract](#8-external-validator-contract)
9. [File-level implementation plan](#9-file-level-implementation-plan)
10. [Test and pressure-test plan](#10-test-and-pressure-test-plan)
11. [Security and safety controls](#11-security-and-safety-controls)
12. [Alternatives and trade-offs](#12-alternatives-and-trade-offs)
13. [Acceptance criteria](#13-acceptance-criteria)
14. [Rollout and compatibility](#14-rollout-and-compatibility)
15. [Open decisions](#15-open-decisions)
16. [Implementation handoff and ownership](#16-implementation-handoff-and-ownership)
17. [Implementation quality bar](#17-implementation-quality-bar)

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
    IkeRequest
        |
        v
    NativeIkeCollector
        |
        v
    IkeParser + response binding
        |
        v
    IkeObservation(s) + typed failure
        |
        v
    existing evaluator -> ScanResult
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
3. #552 IKEv1 Main/Aggressive observation and mandatory Historic/identity/credential findings;
4. #553 IKEv2 binding, unchanged attributes, and inconsistent-selection termination;
5. #554 canonical findings and Rich/JSON/JSONL/CBOM parity;
6. #556 package/image/docs/release verification for the pre-PQC MVP.

Post-MVP milestone `0.14.0 - IKE PQC Parity`: #555 live ML-KEM-768/1024 and legal
ADDKE selection, #562 completion, and #563 discovery parity.

Protected `IKE_INTERMEDIATE`/ADDKE completion is optional, unscheduled, and owned by
[#562](https://github.com/BreachSAFE/qureddy/issues/562). EnXemble validation is owned by
the separate [EnXemble issue #51](https://github.com/BreachSAFE/enxemble/issues/51).

No stage may label an endpoint `PROTECTED` from an advertised or selected PQ
transform alone.

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
- Explicit evidence levels: `observed`, `advertised`, `selected`, `completed`.
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
    -> IkeRequest
    -> CollectorRegistry
    -> NativeIkeCollector
    -> bounded UDP transport
    -> IKE parser and response binder
    -> IkeObservation
    -> CollectionResult
    -> shared evaluator
    -> canonical ScanResult
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
CLI -> Registry: select IKE collector
Registry -> NativeIkeCollector
Collector -> UDP transport: send bounded probe
UDP transport -> Collector: datagram or timeout
Collector -> Parser/binder: parse and bind response
Parser/binder -> Collector: observation or typed failure
Collector -> Evaluator: CollectionResult
Evaluator -> CLI: canonical ScanResult
CLI -> Output projections: render once
Output projections -> caller: Rich / JSON / JSONL / CBOM / bundle
```

`--output-dir` fans out projections from the same `ScanResult`; it never repeats
the network operation.

## 4. Canonical data contract

### 4.1 Request types

The following are the proposed protocol-private models. They are immutable,
strict, and validated at the CLI boundary.

```python
class IkeVersion(StrEnum):
    V1 = "ikev1"
    V2 = "ikev2"

class IkeExchange(StrEnum):
    MAIN = "main"
    AGGRESSIVE = "aggressive"
    SA_INIT = "sa_init"

class IkeTransport(StrEnum):
    UDP = "udp"

class IkeNatTraversal(StrEnum):
    NOT_TESTED = "not_tested"
    NOT_OBSERVED = "not_observed"
    DETECTED = "detected"
    REQUIRED = "required"

class IkeProbeMode(StrEnum):
    DISCOVERY = "discovery"
    OBSERVATION = "observation"

class IkeRequest(BaseModel):
    model_config = FROZEN

    target: ScanTarget
    version: IkeVersion
    exchanges: tuple[IkeExchange, ...]
    ports: tuple[int, ...] = (500, 4500)
    nat_traversal: IkeNatTraversal = IkeNatTraversal.NOT_TESTED
    mode: IkeProbeMode = IkeProbeMode.OBSERVATION
    timeout_seconds: int = Field(ge=1, le=300)
    retries: int = Field(ge=0, le=5)
    request_id: str
```

`ScanTarget` must gain an explicit UDP/IKE representation rather than encoding
transport only in a lossy `locator` string. A target parser must reject ports
outside 1–65535, unsupported schemes, bracket corruption, control characters,
and ambiguous host/port input before any socket is opened.

### 4.2 Algorithm and response types

```python
class IkeResponseState(StrEnum):
    OBSERVED = "observed"
    NO_RESPONSE = "no_response"
    NOTIFY = "notify"
    NO_PROPOSAL = "no_proposal"
    INVALID_KE = "invalid_ke"
    MALFORMED = "malformed"
    FILTERED = "filtered"
    UNSUPPORTED = "unsupported"

class IkeEvidenceLevel(StrEnum):
    OBSERVED = "observed"
    ADVERTISED = "advertised"
    SELECTED = "selected"
    COMPLETED = "completed"

class IkeCollectorRole(StrEnum):
    AUTHORITATIVE = "authoritative"
    CORROBORATING = "corroborating"

class IkeAlgorithmSet(BaseModel):
    model_config = FROZEN

    encryption: tuple[str, ...] = ()
    integrity: tuple[str, ...] = ()
    prf: tuple[str, ...] = ()
    dh_groups: tuple[str, ...] = ()
    kem_groups: tuple[str, ...] = ()
    signatures: tuple[str, ...] = ()
    raw_attribute_ids: tuple[int, ...] = ()

class IkeObservation(BaseModel):
    model_config = FROZEN

    request_id: str
    collector: str
    collector_version: str
    collector_role: IkeCollectorRole
    source: ScanTarget
    version: IkeVersion
    exchange: IkeExchange
    transport: IkeTransport
    destination_port: int
    address_family: str
    response_state: IkeResponseState
    evidence_level: IkeEvidenceLevel
    offered: IkeAlgorithmSet
    selected: IkeAlgorithmSet | None = None
    nat_traversal: IkeNatTraversal
    vendor_ids: tuple[str, ...] = ()
    notify_types: tuple[str, ...] = ()
    spi_i: str | None = None
    spi_r: str | None = None
    message_id: int | None = None
    raw_digest: str | None = None
    evidence_refs: tuple[str, ...] = ()
```

Raw packet bytes are retained only as a bounded, content-addressed artifact
reference. They must not be placed in default stdout or embedded unboundedly in
JSON/CBOM. Secrets, credentials, PSK material, and authentication hashes are
never model fields.

### 4.3 Result integration

`CollectionResult` remains the acquisition boundary. The implementation must
choose one canonical representation for the scanner result and avoid populating
parallel, contradictory fields. The preferred shape is:

```python
CollectionResult(
    collector="native-ike",
    collector_version="<package-version>",
    evidence=(ike_observation_as_evidence,),
    findings=ike_findings,
    provenance=provenance,
    failure=typed_failure_or_none,
    scan_result=None,  # evaluator fills the one canonical ScanResult downstream
)
```

The evaluator derives `ScanResult` exactly once. If the existing lifecycle is
changed so collectors return `ScanResult` directly, remove `scan_result` from
`CollectionResult` in the same compatibility change; do not add an IKE-specific
third result shape.

### 4.4 Contract closure gates

The model inventory above is necessary but not sufficient for implementation. The
following gaps are release-blocking design work:

| Gap | Required closure |
|---|---|
| Duplicate IKE enum vocabulary | One canonical owner for version, exchange, NAT-T, transport, and evidence-level types |
| TLS-shaped dependency field | Replace protocol-specific unions with one neutral tool/provenance dependency model |
| Completion truth | Store coverage completion once; derive aggregate sweep status from receipts |
| Validator result | Define a versioned status/provenance model for EnXemble `ike-scan` corroboration |
| Evaluation mapping | Specify exact neutral facts, reason codes, and IKE-axis rules before renderer work |
| Current `ScanResult` seam | Reconcile the proposed additive fields with the actual model and preserve TLS/SSH bytes |

No implementation issue may introduce a second type for any row above. The public
observation is the only IKE object consumed by evaluation or output; wire/parser
objects remain private.

## 5. IKE protocol contract

### 5.1 Probe behavior

The first implementation sends bounded, unauthenticated discovery/observation
requests. It may use IKEv1 Main/Aggressive discovery and IKEv2 `IKE_SA_INIT`, but
it never proceeds to authentication or tunnel setup. Each request has a unique
SPI and request fingerprint.

```text
construct request
  -> send UDP/500 or UDP/4500
  -> accept only expected source and destination
  -> validate version, exchange, flags, SPI, message ID, declared length
  -> validate request fingerprint and payload bounds
  -> validate response against the offered proposal set
  -> classify response state
  -> preserve raw digest and typed observation
```

### 5.2 Evidence ladder

| Level | Meaning | HNDL consequence |
|---|---|---|
| `observed` | Packet/notify behavior was parsed and bound to this request | Evidence only |
| `advertised` | Peer advertised a capability or transform | Never `PROTECTED` |
| `selected` | Peer selected an offered transform | Still not completed PQ protection |
| `completed` | Applicable exchange completed with transcript validation | Candidate for protection evaluation |

An accepted classical transform is useful HNDL/downgrade evidence. A selected
ADDKE or ML-KEM transform is not proof of a completed KEM exchange. UDP silence,
filtered traffic, malformed data, and unsupported local capabilities remain
explicit non-positive/unknown states.

### 5.3 Response binding requirements

The parser must reject or classify as non-positive:

- wrong source address or destination port;
- wrong IKE version, exchange type, response flag, SPI, or message ID;
- a response that cannot be bound to the unique request SPI, exchange, message ID,
  source, retry state, and offered-proposal fingerprint; IKEv2 does not echo the initiator nonce
  in `IKE_SA_INIT`, so nonce equality is never used as a binding requirement;
- duplicate, replayed, truncated, oversized, or length-inconsistent datagrams;
- payload chains that exceed declared bounds or contain unknown critical payloads;
- selected transforms not present in the offered proposal set;
- forged SA selections and incomplete intermediate exchanges.

The known forged-response fixture that previously produced `HNDL: PROTECTED` is a
release blocker until it remains non-`PROTECTED` through the real CLI and every
output format.

## 6. CLI contract

### 6.1 Command

```console
qureddy scan ike TARGET[:PORT]
```

Examples:

```console
# Probe both standard IKE ports with the default IKEv2 observation profile.
qureddy scan ike vpn.example.com

# Explicit port and IPv6 literal.
qureddy scan ike 203.0.113.10:500 --port 500
qureddy scan ike '[2001:db8::10]:4500' --port 4500

# Request both protocol families and verbose packet-stage diagnostics.
qureddy scan ike vpn.example.com --ike-version auto --exchange sa-init --ikev1 --vvv

# Machine-readable output and a complete one-scan bundle.
qureddy scan ike vpn.example.com --format json
qureddy scan ike vpn.example.com --format jsonl
qureddy scan ike vpn.example.com --format cbom
qureddy scan ike vpn.example.com --output-dir run/
```

The exact option spelling must follow the existing Typer option conventions; the
implementation must not introduce aliases that collide with global verbosity or
output options. `--output-dir` writes the same bundle contract used by TLS/SSH.

The first release exposes no completion-mode CLI option. A future completion
option belongs to #562 and cannot be implied by `--exchange`, `--ike-version`,
or a selected ADDKE/ML-KEM transform.

### 6.2 Proposed options

| Option | Default | Contract |
|---|---:|---|
| `--ike-version` | `ikev2` | `ikev1`, `ikev2`, or `auto`; `auto` never upgrades unknown to secure |
| `--exchange` | `sa-init` | `sa-init`, `main`, `aggressive`, or `auto` |
| `--port` | `500`/profile | UDP 500 or 4500 only for the first release |
| `--nat-t` | `auto` | probe/require/disable NAT-T behavior |
| `--timeout` | existing default | per-datagram timeout, bounded by existing limits |
| `--retries` | existing default | bounded retransmission, no unbounded loop |
| `--format` | `rich` | `rich`, `json`, `jsonl`, `cbom` |
| `--output` | none | one selected output file |
| `--output-dir` | none | all supported projections from one result |
| `-v/-vv/-vvv` | 0 | diagnostics only; never changes evidence |
| `--log` | none | structured diagnostic log, separate from machine stdout |

No CLI option accepts a PSK, XAUTH username/password, `HASH_R`, or a tunnel
configuration. Those features are explicitly rejected as out of scope.

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
IkePolicyFacts(
    version=IkeVersion.V2,
    response_state=IkeResponseState.OBSERVED,
    evidence_level=IkeEvidenceLevel.SELECTED,
    classical_algorithms=("AES-CBC", "HMAC-SHA1", "MODP-1536"),
    pq_algorithms=("ML-KEM-768",),
    downgrade_observed=True,
    nat_t=IkeNatTraversal.DETECTED,
    authenticated=False,
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

### 7.2 Required semantic rules

1. A classical-only accepted proposal can produce HNDL `AT_RISK` or
   `PROTECTED_DEFEASIBLE` according to the existing policy, with named
   algorithms and evidence references.
2. IKEv1 discovery never implies PQ support.
3. `advertised` or `selected` PQ evidence never implies completed protection.
4. `completed` is not part of the observation release. Protected
   `IKE_INTERMEDIATE`/ADDKE completion requires the separate, unscheduled #562
   decision and provider/security/conformance gates.
5. No response, filtering, malformed packets, and unsupported local capability
   produce `UNKNOWN`/`NOT_TESTABLE`, not a favorable posture.
6. A corroborator disagreement is preserved as evidence and cannot silently
   improve the posture.

The observation provider exposes only capability reporting, randomness, valid
KE-share generation, and bounded disposal. It does not expose shared-secret
derivation, IKE KDFs, encryption/decryption, integrity, `derive`, `protect`,
`verify`, or transcript completion. Those completion-only methods belong to #562
and are not required by #551--#555.

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

EnXemble’s descriptor can run QuReddy as the primary tool and `ike-scan` as an
optional independent validator/corroborator. The validator checks the primary
result’s IKEv1 claims; it does not decide PQ readiness.

```yaml
id: qureddy-ike
title: "HNDL Audit (IKE/IPsec)"
run:
  base: [qureddy, scan, ike]
  image: ghcr.io/breachsafe/qureddy:latest
  positional_from: "{host}:{port}"
  output_dir_flag: "--output-dir"
  artifacts:
    - { name: json, file: scan.json, primary: true }
    - { name: jsonl, file: scan.jsonl }
    - { name: cbom, file: scan.cdx.json }
validate:
  argv: ["ike-scan", "--retry=1", "{host}"]
  role: corroborating
  scope: [ikev1, transform, vendor_id, nat_t]
  badge_rule:
    pass_if: { exit: 0, parsed_handshake: true }
    fail_if: { exit: 0, parsed_conflict: true }
    otherwise: unavailable
```

The exact descriptor field name (`role`/`scope` or a schema-approved equivalent)
must be implemented in EnXemble before this example is shipped. An exit code of
zero with no parsed handshake is unavailable/indeterminate, never a pass.

### 8.2 Provenance and disagreement

```python
ValidatorObservation(
    validator="ike-scan",
    version="1.9.5",
    role="corroborating",
    target="vpn.example.com:500",
    status="pass|conflict|unavailable",
    parsed_facts={...},
    evidence_refs=(...),
)
```

The validator result is attached to provenance/evidence. It cannot replace the
native `IkeObservation`, change the authoritative collector role, or upgrade
`hndl_exposure` by itself.

## 9. File-level implementation plan

### 9.1 QuReddy files to change

| File | Change | Must not do |
|---|---|---|
| `src/qureddy/core/contracts.py` | Add IKE source/capability/policy enums and typed adapter seam | Put packet parsing here |
| `src/qureddy/core/models.py` | Add supported IKE scheme/target fields only if shared target model can remain lossless | Re-declare hostname/port validation |
| `src/qureddy/core/targets.py` | Parse and normalize UDP IKE targets | Open sockets or infer posture |
| `src/qureddy/core/registry.py` | Map IKE source to native collector deterministically | Select by renderer or output format |
| `src/qureddy/collectors/native.py` | Register `NativeIkeCollector` and preserve lifecycle | Duplicate scanner logic |
| `src/qureddy/scanners/ike/__init__.py` | Public protocol-private package boundary | Export renderer internals |
| `src/qureddy/scanners/ike/models.py` | `IkeRequest`, enums, `IkeAlgorithmSet`, `IkeObservation` | Store secrets or unbounded packets |
| `src/qureddy/scanners/ike/packet.py` | Bounded encoder/decoder and payload-chain validation | Implement cryptographic primitives |
| `src/qureddy/scanners/ike/probe.py` | UDP transport, timeout, retry, source binding, packet capture digest | Authenticate or establish a tunnel |
| `src/qureddy/scanners/ike/parser.py` | Parse IKEv1/v2 headers, SA/KE/Notify/NAT-T evidence | Decide HNDL posture |
| `src/qureddy/scanners/ike/bind.py` | Request/response correlation and anti-forgery checks | Accept unsolicited selection |
| `src/qureddy/scanners/ike/classify.py` | Map observations to neutral policy facts | Render user-facing text |
| `src/qureddy/scanners/common/finding_types.py` | Add protocol-neutral IKE finding identifiers | Add IKE-specific output code |
| `src/qureddy/scanners/common/posture.py` | Apply shared readiness/HNDL rules to IKE facts | Reimplement TLS/SSH policy |
| `src/qureddy/cli/ike.py` | Typer command, shared options, one execute/render path | Bypass `CollectorRegistry` |
| `src/qureddy/cli/main.py` | Register `scan ike` and help text | Duplicate exit-code constants |
| `src/qureddy/output/*` | Only generic enum/field projection updates | Import `scanners/ike/*` parsers |
| `src/qureddy/output/cbom_*` | Add validated IKE component/provenance mapping after schema gate | Emit unsupported PQ claims |
| `docs/reference/cli.md` | Document the stable command/options/exit behavior | Promise completion before it exists |
| `docs/architecture/scan-contract.md` | Add IKE to the generic collector contract | Create a source-specific output path |
| `docs/explanation/architecture.md` | Add IKE flow and boundary diagrams | Describe unimplemented features as shipped |
| `CHANGELOG.md` | Add entries only at release time | Put future claims in an old release |

### 9.2 Tests and fixtures to add

| File | Coverage |
|---|---|
| `tests/test_ike_models.py` | strict model validation, ports, enums, immutability |
| `tests/test_ike_targets.py` | hostname/IP/IPv6/port/control-character cases |
| `tests/test_ike_packet.py` | length, payload-chain, critical-payload, truncation cases |
| `tests/test_ike_parser.py` | parser-negative byte corpus and notify classification; positive negotiation is live-only |
| `tests/test_ike_binding.py` | wrong SPI/source/version/message ID/proposal/duplicates; no echoed-nonce assumption |
| `tests/test_ike_probe.py` | timeout/retry/NAT-T/filtered behavior with a real UDP fixture |
| `tests/test_ike_scanner.py` | canonical `CollectionResult` and typed failures |
| `tests/test_ike_policy.py` | evidence ladder and HNDL semantics |
| `tests/test_ike_cli.py` | real installed CLI parsing, help, exit codes, output flags |
| `tests/test_ike_output.py` | Rich/JSON/JSONL parity and output-dir single acquisition |
| `tests/test_ike_cbom.py` | CycloneDX validation and consumer compatibility |
| `tests/fixtures/ike/*.bin` | malformed/forged parser-safety inputs only; never positive negotiation evidence |
| `tests/live/test_live_ike.py` | opt-in strongSwan/veepin lab interoperability |
| `tests/fuzz/fuzz_ike_packet.py` | parser non-crash and bounded-resource properties |

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

1. Read current contracts, issues, ADRs, and skills; record source-of-truth paths.
2. Write the failing test or deterministic fixture before implementation.
3. Reproduce the failure in an isolated `/tmp` workstream.
4. Steelman two designs and record the kill-shot for the rejected design.
5. Implement the smallest seam-preserving change.
6. Run unit, property, parser-fuzz, and architecture-boundary tests.
7. Run real installed CLI commands for every option and output format.
8. Run the container CLI and the private strongSwan/veepin interoperability lab.
9. Run quality, anti-pattern, supply-chain, documentation, and release gates.
10. Review the diff, update issue/ADR/changelog, then commit/release only after
    all required evidence is recorded.

### 10.1 Required lab matrix

| Fixture/peer | Expected proof |
|---|---|
| Classical IKEv1 responder | version/mode/transform evidence; HNDL risk named |
| IKEv1 Aggressive responder | discovery only; no PSK/hash capture |
| Classical IKEv2 responder | classical proposal selected; no PQ claim |
| PQ-capable strongSwan/veepin responder | advertised/selected state; completion claim gated |
| `NO_PROPOSAL_CHOSEN` | typed notify, no success inference |
| COOKIE retry | bounded retry and correct correlation |
| filtered UDP | `filtered`/unknown, not secure |
| forged/wrong-SPI response | non-positive; never `PROTECTED` |
| malformed/truncated payload | typed parse failure; process remains alive |
| EnXemble + `ike-scan` disagreement | explicit corroborator conflict |

### 10.2 Real CLI commands

The acceptance run must use the built wheel or image, not Python importing Python:

```console
qureddy --version
qureddy scan ike vpn.example.com -vvv
qureddy scan ike vpn.example.com --format json --output scan.json
qureddy scan ike vpn.example.com --format jsonl --output scan.jsonl
qureddy scan ike vpn.example.com --format cbom --output scan.cdx.json
qureddy scan ike vpn.example.com --output-dir run/
docker run --rm ghcr.io/breachsafe/qureddy:<release> scan ike vpn.example.com -vvv
```

Each command’s exit code, stdout, stderr, files, and parsed evaluation must be
recorded. A command that is not run is reported `NOT RUN`, never assumed passing.

## 11. Security and safety controls

- Use `subprocess` nowhere in native IKE collection; use a bounded UDP socket
  with explicit address and timeout handling.
- Never accept a response solely because it has a parseable SA payload.
- Bind response to request SPI, request fingerprint, source, exchange, flags, and
  message ID before classifying any selected algorithm. Do not require an echoed
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

The selected architecture is **8/10 before implementation**: the boundaries and
evidence semantics are explicit, but execution readiness remains zero until the
forged-response failure, lifecycle prerequisites, and real lab gates pass. It can
be called 10/10 only after the acceptance criteria below are demonstrated.

## 13. Acceptance criteria

- [ ] Existing collector lifecycle is live for the IKE CLI; no direct scanner
      bypass remains.
- [ ] Target/request models are strict, immutable, and lossless for UDP/500/4500.
- [ ] Parser-negative fixtures parse deterministically; every positive negotiation
      and readiness claim comes from a live authorized IPsec peer.
- [ ] Source/SPI/version/exchange/flags/message-ID/retry-state/proposal binding rejects
      forged and replayed responses.
- [ ] Advertised, selected, and completed are distinct; first release never emits
      `PROTECTED` for advertised/selected-only evidence.
- [ ] IKEv1 evidence never becomes PQ support.
- [ ] No response/filtering/malformed/unsupported states remain explicit.
- [ ] Rich, JSON, JSONL, CBOM, and `--output-dir` have parity from one result.
- [ ] Built wheel and container commands pass the lab matrix with recorded output.
- [ ] Parser fuzzing, mutation/negative fixtures, architecture-boundary checks, and
      real CLI tests pass.
- [ ] EnXemble `ike-scan` validator reports pass/conflict/unavailable correctly;
      exit-0/no-handshake is not pass.
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

1. Which CycloneDX 1.7 component/protocol mapping is accepted by Qurum and
   mint-oscal before CBOM admission?
2. Which real FortiGate/strongSwan interoperability endpoints can be used under
   the approved test authorization?

Provider selection, IKEv1/IKEv2 sequencing, validator ownership, and completion
scope are decided by #546 and its child issues; they are not open decisions here.

## 16. Implementation handoff and ownership

This section mirrors the child-issue ownership in #546 for milestones `0.10.0`
through `0.14.0`; #546 remains the normative contract.

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
                                public IKE observation
                                          |
                                          +--> coverage receipt
                                          +--> neutral policy facts
                                          |
                                          v
                                    CollectionResult
                                          |
                                          v
                                      ScanResult
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
IkeScanConfig                 CLI/profile defaults; one owner
IkeProbeRequest               one concrete wire attempt; private
ParsedIkeResponse             syntactically parsed, still untrusted; private
ValidatedIkeResponse          request-bound response; private constructor
IkeProposalObservation        public positive/negative observation; one output input
CoverageReceipt               planned/attempted/accepted/rejected/unknown/not-tested
CollectionResult              acquisition boundary
ScanResult                    evaluator boundary and renderer input
ValidatorObservation          EnXemble corroborator provenance, separate from evidence
```

Do not create parallel `IkeVersion`, `IkeExchange`, `EvidenceLevel`, transport,
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
0.12.0  canonical findings, all outputs, coverage, EnXemble validator
0.13.0  real ADDKE/ML-KEM selection evidence
0.14.0  package/image/docs/release verification
        optional completion is unscheduled in #562
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

### References

- [RFC 5996 — IKEv2](https://www.rfc-editor.org/info/rfc5996)
- [RFC 9242 — IKE_INTERMEDIATE](https://www.rfc-editor.org/info/rfc9242)
- [RFC 9370 — Additional Diffie-Hellman exchanges](https://www.rfc-editor.org/info/rfc9370)
- [ike-scan project](https://github.com/royhills/ike-scan)
- [EnXemble descriptor architecture](https://github.com/BreachSAFE/enxemble/blob/docs/readme-tuneup/README.md)
