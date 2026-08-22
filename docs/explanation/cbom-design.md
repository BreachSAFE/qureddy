# CBOM design and CycloneDX interoperability

Why `--format cbom` is shaped the way it is, and what a consumer can rely on.

## Contents

1. [Two consumers, different needs](#1-two-consumers-different-needs)
2. [The document shape](#2-the-document-shape-native-cyclonedx-throughout)
3. [What a consumer can rely on](#3-what-a-consumer-can-rely-on)
4. [Decision: native structures](#4-decision-native-structures-settled)

## 1. Two consumers, different needs

A scan produces three kinds of information: the observed cryptographic assets
(KEX groups, cipher suites, protocols, the leaf certificate and its signature
algorithm), QuReddy's interpretation (per-finding severity, the readiness
verdict), and the provenance trail (the exact probe command, return code, output
hashes, observation type, source module).

Two classes of consumer want different subsets:

- Generic CycloneDX tooling (IBM CBOMkit, Dependency-Track's crypto support, any
  CycloneDX 1.7 validator or SBOM platform) acts on the crypto asset inventory and
  its post-quantum posture.
- QuReddy-aware consumers, chiefly Qurum, want the full fidelity including the
  interpretation and provenance.

A CBOM is, in CycloneDX's own document-type model, an inventory. Findings and
"is this exploitable" statements belong to a separate VEX or vulnerability
document. The full scan report already exists in `--format json` (the
`qureddy.scan.v1` contract).

## 2. The document shape: native CycloneDX throughout

Every kind of information rides in a native CycloneDX 1.7 structure. There is no
separate flat `qureddy:` findings/evidence dump.

1. Native crypto layer. Every observed asset is a real `component` with native
   `cryptoProperties`. Algorithms carry `algorithmProperties` (primitive,
   parameterSetIdentifier, nistQuantumSecurityLevel, cryptoFunctions): KEX groups,
   the negotiated AEAD cipher suite, and certificate/host-key signature algorithms
   are all classified (X25519MLKEM768 as ML-KEM-768 at NIST category 3 per FIPS
   203; classical signatures such as ECDSA/RSA/EdDSA at level 0; ML-DSA at its FIPS
   204 category). Protocols carry `protocolProperties`, the certificate carries
   native `certificateProperties`, and a native `dependencies[].provides` graph
   ties the assets to the endpoint. Only algorithms QuReddy can classify with
   confidence are annotated; an unknown name keeps a minimal `algorithmProperties`
   rather than a fabricated value.

2. Evidence as occurrences. Each observation is attached to the crypto asset it
   describes as a `component.evidence.occurrences` entry. The probe provenance —
   observation type, role, expected group, return code, the full `command_sha256`,
   and duration — rides in the occurrence `additionalContext` string.

3. Findings as annotations. Each finding is a top-level CycloneDX `annotation`
   whose `subjects` link to the asset it concerns. `annotator` is the QuReddy tool
   component, `timestamp` is the real scan completion time, and `text` is the
   finding title plus its full description, including any standards citations.

4. Verdict as component properties. Each finding's machine verdict rides on its
   subject component as `qureddy:readiness`, `qureddy:severity`, and
   `qureddy:rule_id` properties, so a consumer reads the verdict as queryable
   fields instead of parsing prose.

5. Provenance layer. Scan, target, and tool provenance
   (`qureddy:scan.*`, `qureddy:target.*`, `qureddy:openssl.*`, including the
   run-level `qureddy:scan.readiness` and `qureddy:scan.status`) remain as
   `qureddy:`-namespaced `metadata.properties`. `properties` is a first-class
   CycloneDX extension point, so these keep the document valid and are ignored
   gracefully by any tool that does not understand them.

Content addressing is opt-in: `--reproducible` omits the per-run identity fields
(serialNumber, metadata timestamp, scan id and timing, evidence duration, the
host-specific OpenSSL path, retry-varying attempt count) and pins every annotation
`timestamp` to the Unix epoch, so the same scan is byte- and digest-identical.

## 3. What a consumer can rely on

- The document is valid CycloneDX 1.7 and parses in every 1.7 tool. There is no
  tool it breaks; worst case for an unaware tool is that the annotations,
  occurrences, and `qureddy:` verdict properties are inert, never that ingestion
  fails.
- Crypto-aware tools understand the full crypto inventory and post-quantum posture
  natively, with no CVE identifiers required.
- Findings, evidence, and the machine verdict are native CycloneDX: findings are
  top-level annotations, evidence is occurrences on the asset, and the verdict is
  queryable `qureddy:` properties on the subject component. A generic tool that does
  not read the `qureddy:` verdict keys still ingests the document; the same
  information is also in `--format json`.
- Version floor: `cryptoProperties` is CycloneDX 1.6+ and this document is 1.7, so
  tooling pinned to CycloneDX 1.6 or earlier will reject or not understand it.
- Prowler and TAO consume QuReddy's `--format json` (`qureddy.scan.v1`) through the
  endpoint collector, not the CBOM as CycloneDX.

## 4. Decision: native structures (settled)

The CBOM is a lean, valid CycloneDX 1.7 document that carries findings, evidence,
and the machine verdict in native CycloneDX structures — annotations, occurrences,
and component properties — over the native crypto layer, with only scan/target/tool
provenance left in `qureddy:` `metadata.properties`.

This is the planned graduation of the settled #169 decision, not a reversal. #169
resolved to prefer native CycloneDX "where clean" and kept a flat extension layer
only where native modelling was not yet clean; #147/#149 had explicitly deferred
`occurrences` and `annotations` as "the richer alternative". #287 (shipped 0.2.23)
completes that move: it replaces the earlier flat `qureddy:finding.NN.*` /
`qureddy:evidence.NN.*` `metadata.properties` blocks with occurrences, annotations,
and verdict properties. Generic tools still ignore the `qureddy:` verdict keys
without choking, and the native `algorithmProperties` (notably
`nistQuantumSecurityLevel`), protocol components, and cipher strength carry enough
for a foreign consumer to *derive* the weak-crypto / quantum-vulnerable findings
themselves. QuReddy and Qurum read the explicit findings from the annotations and
verdict properties. We deliberately do NOT re-model findings as CycloneDX
`vulnerabilities` (see below). Issue #169 closed.

### Rationale against `vulnerabilities`

The alternative considered was re-modelling findings as CycloneDX `vulnerabilities`
with `ratings` so foreign tools understand them natively. It was rejected: PQ-readiness
has no CVE identifier, so a `vulnerability` entry needs a synthetic id that a generic
scanner would surface as a non-CVE finding, polluting vulnerability dashboards. The
interoperability gain does not justify that, especially since the weak-crypto
conclusion is already derivable from the native `nistQuantumSecurityLevel`. Modelling
findings as annotations keeps them native and queryable without that pollution. If a
third party ever needs a machine-readable posture artifact, a separate CycloneDX VEX
is the correct vehicle, not overloading the inventory.
