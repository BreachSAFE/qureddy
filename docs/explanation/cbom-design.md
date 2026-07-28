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

## Open question

Whether to make the interpretation layer natively understood by foreign tools by
re-modelling findings as CycloneDX `vulnerabilities` + `ratings` and evidence as
`components[].evidence`, versus keeping the CBOM a lean native inventory and
leaving the report to `--format json` (and, if a machine-readable posture artifact
is needed for third parties, a separate CycloneDX VEX).

The caution against `vulnerabilities`: PQ-readiness has no CVE identifier, so
modelling it as a vulnerability requires synthetic ids that a generic scanner would
surface as non-CVE findings. This is an interoperability-versus-semantic-honesty
trade and a product decision rather than a code constraint. Tracked in issue #169.
