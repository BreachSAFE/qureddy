# CBOM design and CycloneDX interoperability

Why `--format cbom` is shaped the way it is, and what a consumer can rely on.

## Two consumers, different needs

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

## The decision: one valid CycloneDX 1.7 document, two layers

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

2. Extension layer. The interpretation and provenance (per-finding verdicts,
   readiness, scan/target metadata, OpenSSL capability flags, the evidence trail)
   are carried as `qureddy:`-namespaced `metadata.properties`. `properties` is a
   first-class CycloneDX extension point, so these keep the document valid and are
   ignored gracefully by any tool that does not understand them.

Content addressing is opt-in: `--reproducible` omits the per-run identity fields
(serialNumber, timestamp, scan id and timing, evidence duration, the host-specific
OpenSSL path, retry-varying attempt count) so the same scan is byte- and
digest-identical.

## What a consumer can rely on

- The document is valid CycloneDX 1.7 and parses in every 1.7 tool. There is no
  tool it breaks; worst case for an unaware tool is that the extension layer is
  inert, never that ingestion fails.
- Crypto-aware tools understand the full crypto inventory and post-quantum posture
  natively, with no CVE identifiers required.
- The interpretation layer is semantically private: a generic tool sees the crypto
  inventory but not the findings, verdict, or evidence. Those are also in
  `--format json`.
- Version floor: `cryptoProperties` is CycloneDX 1.6+ and this document is 1.7, so
  tooling pinned to CycloneDX 1.6 or earlier will reject or not understand it.
- Prowler and TAO consume QuReddy's `--format json` (`qureddy.scan.v1`) through the
  endpoint collector, not the CBOM as CycloneDX.

## Decision (settled)

Keep the CBOM as-is: a lean, valid CycloneDX 1.7 with a native crypto layer plus
the `qureddy:` extension layer. Generic tools ignore the extensions without
choking, and the native `algorithmProperties` (notably `nistQuantumSecurityLevel`),
protocol components, and cipher strength carry enough for a foreign consumer to
*derive* the weak-crypto / quantum-vulnerable findings themselves. QuReddy and
Qurum read the explicit findings from the extension layer. We deliberately do NOT
re-model findings as CycloneDX `vulnerabilities` (see below). Issue #169 closed.

### Rationale against `vulnerabilities`

The alternative considered was re-modelling findings as CycloneDX `vulnerabilities`
+ `ratings` (and evidence as `components[].evidence`) so foreign tools understand
them natively. It was rejected: PQ-readiness has no CVE identifier, so a
`vulnerability` entry needs a synthetic id that a generic scanner would surface as a
non-CVE finding, polluting vulnerability dashboards. The interoperability gain does
not justify that, especially since the weak-crypto conclusion is already derivable
from the native `nistQuantumSecurityLevel`. If a third party ever needs a
machine-readable posture artifact, a separate CycloneDX VEX is the correct vehicle,
not overloading the inventory.
