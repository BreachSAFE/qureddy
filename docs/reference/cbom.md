# CycloneDX 1.7 CBOM reference

`--format cbom` emits a CycloneDX 1.7 JSON Cryptography Bill of Materials
(CBOM). The document contains cryptographic assets that QuReddy positively
observed, scanner and collector provenance, scan status, and an endpoint
relationship graph.

## Contents

1. [Interoperability](#1-interoperability)
2. [Document identity](#2-document-identity)
3. [Metadata](#3-metadata)
4. [Endpoint root](#4-endpoint-root)
5. [Tool provenance](#5-tool-provenance)
6. [Cryptographic assets](#6-cryptographic-assets)
7. [Relationships](#7-relationships)
8. [Scan status](#8-scan-status)
9. [Stable references and volatile fields](#9-stable-references-and-volatile-fields)
10. [Positive observation rule](#10-positive-observation-rule)
11. [Certificate fields](#11-certificate-fields)
12. [Reproducibility](#12-reproducibility)
13. [Validation contract](#13-validation-contract)
14. [Evidence limits](#14-evidence-limits)
15. [Related documentation](#15-related-documentation)

## 1. Interoperability

The document is structured in two layers (see
[CBOM design](../explanation/cbom-design.md)):

1. A native crypto layer. Observed algorithms, protocols, and the certificate are
   real CycloneDX `components` with native `cryptoProperties`
   (`algorithmProperties`/`protocolProperties`/`certificateProperties`) and a
   native `provides` graph. Any CycloneDX 1.7, crypto-aware tool (for example IBM
   CBOMkit or Dependency-Track's crypto support) understands this layer, including
   the post-quantum posture, with no CVE identifiers required.
2. A `qureddy:`-namespaced property layer under `metadata.properties`. QuReddy's
   interpretation (per-finding verdicts, readiness) and the provenance trail live
   here. `properties` is a valid CycloneDX extension point, so the document stays
   valid and a tool that does not understand these keys ignores them; it never
   fails ingestion. QuReddy-aware consumers (Qurum) read the full fidelity.

Consequences: the document parses in every CycloneDX 1.7 tool; the crypto
inventory is natively understood; the interpretation layer is semantically private
to QuReddy-aware readers. Because `cryptoProperties` is CycloneDX 1.6+ and this
document is 1.7, tooling pinned to CycloneDX 1.6 or earlier will not accept it. The
full scan report, including findings, is also available in `--format json`.

## 2. Document identity

| Field | Value |
| --- | --- |
| `bomFormat` | `CycloneDX` |
| `specVersion` | `1.7` |
| `$schema` | `http://cyclonedx.org/schema/bom-1.7.schema.json` |
| `version` | CycloneDX document revision, currently `1` |

The final JSON bytes, not an intermediate Python model, are the output
contract.

## 3. Metadata

`metadata` contains:

- a generated UTC timestamp;
- the remote endpoint as `metadata.component`;
- QuReddy and the usable local OpenSSL collector under
  `metadata.tools.components`;
- QuReddy scan status properties.

The metadata component is the graph root. It is not duplicated in
`components`.

## 4. Endpoint root

The endpoint root has:

| Field | Contract |
| --- | --- |
| `type` | `application` |
| `name` | normalized `host:port` |
| `bom-ref` | `endpoint` |

`application` represents the observed remote endpoint in the CycloneDX
component model. QuReddy does not infer a remote product name, version, vendor,
package, or implementation.

## 5. Tool provenance

QuReddy appears as:

```text
bom-ref: tool/qureddy
type: application
name: qureddy
version: installed scanner version
```

A usable local OpenSSL collector appears as:

```text
bom-ref: tool/openssl
type: application
name: openssl
version: observed local version
property: qureddy:collector.role=local-probe-runtime
```

OpenSSL is omitted when the local capability check fails. The collector is
tool provenance, not a component supplied by or depended on by the endpoint.
SSH CBOMs contain QuReddy tool provenance and no OpenSSL tool.

## 6. Cryptographic assets

Observed assets use CycloneDX component type `cryptographic-asset`.

### Algorithms

Each unique positively observed key exchange or certificate signature
algorithm becomes a component with:

```text
bom-ref: crypto/algorithm/<lowercase-observed-name>
cryptoProperties.assetType: algorithm
```

### Protocols

Each unique observed protocol and version becomes a component with:

```text
bom-ref: crypto/protocol/<protocol>-<lowercase-version>
cryptoProperties.assetType: protocol
```

TLS protocol components may include observed cipher suites and references to
their observed algorithms. SSH produces a protocol component for SSH 2.0.

### Certificate

When the TLS certificate probe captures and parses a leaf certificate, the
CBOM contains:

```text
bom-ref: crypto/certificate/leaf
cryptoProperties.assetType: certificate
```

See [certificate fields](#certificate-fields) for the populated properties and
limits.

## 7. Relationships

The endpoint dependency entry uses `provides` to reference each positively
observed algorithm, protocol, and certificate:

```json
{
  "ref": "endpoint",
  "provides": [
    "crypto/algorithm/example",
    "crypto/protocol/ssh-2.0"
  ]
}
```

References are sorted and unique. QuReddy does not emit an endpoint
`dependsOn` edge to the local OpenSSL collector.

## 8. Scan status

CycloneDX metadata properties preserve the execution state:

| Property | Presence | Meaning |
| --- | --- | --- |
| `qureddy:scan.status` | always | `completed` or the top-level failure category |
| `qureddy:scan.failure_category` | on typed failure | Canonical failure category |

A schema-valid sparse CBOM is not proof of a successful scan. Consumers must
read these properties and preserve failure or unknown states.

## 9. Stable references and volatile fields

The endpoint and component `bom-ref` values are deterministic for the same
observations. Component and relationship order is deterministic.

CycloneDX requires run-level identity and time fields that change:

- top-level `serialNumber`;
- `metadata.timestamp`.

Conformance tests normalize only those two fields before comparing repeated
renders. All remaining bytes must be identical for the same fixture.

## 10. Positive observation rule

CBOM inventory includes evidence with observation type:

```text
negotiated
offered
observed
```

`inferred` and `not_testable` evidence does not create cryptographic asset
components. Missing evidence remains missing instead of becoming a favorable
asset claim.

## 11. Certificate fields

The leaf certificate component may contain:

- subject name;
- issuer name;
- X.509 format;
- validity start and end times when the OpenSSL date text parses;
- certificate serial number;
- a reference to the observed signature algorithm.

The component does not establish:

- certificate path or trust;
- hostname validation;
- revocation status;
- private key possession;
- subject public key algorithm or size when not independently derived.

Self-signed classification in QuReddy evidence requires signature verification;
subject and issuer string equality alone is not accepted as proof.

## 12. Reproducibility

By default the CBOM carries per-run identity (a CycloneDX `serialNumber` and
`metadata.timestamp`, plus `qureddy:scan.id` and the scan start/finish times),
so two runs of the same scan produce different bytes. Pass `--reproducible` to
omit those fields: the same observed crypto then yields byte- and
digest-identical output for content addressing. The crypto inventory, ordering,
and values are identical either way.

## 13. Validation contract

QuReddy runs the semantic checks on every document it emits, at runtime, before
writing any bytes. Two heavier layers validate the generator in CI rather than
per document:

1. the official CycloneDX 1.7.1 JSON schemas pinned by commit and SHA-256 (CI conformance);
2. `cyclonedx-cli` 0.33.1 from a checksum-verified release asset (CI conformance);
3. QuReddy semantic checks (runtime, every document).

Layers 1 and 2 gate the release over the generator and its fixture matrix; they
are not a per-document runtime step (`cyclonedx-cli` is an external binary). The
runtime semantic checks reject:

- a `specVersion` other than exactly `1.7`;
- duplicate `bom-ref` values;
- dangling `dependsOn`/`provides`, `signatureAlgorithmRef`, and cipher-suite
  algorithm references;
- secret-like fields or material.

The fixture matrix contains positive and negative cases with provenance
sidecars. The installed console canary validates successful and failed scan
bytes and render determinism.

## 14. Evidence limits

The CBOM is an observation artifact for one target and one scan. It is not:

- a complete host, application, source, binary, key, or certificate inventory;
- remote software identification;
- proof of certificate trust or revocation;
- proof of FIPS validation;
- a compliance conclusion;
- a claim about algorithms that the endpoint did not expose to the probe.

Interpret CBOM entries as observations from the selected collector. The output does
not establish complete inventory, remote implementation identity, certificate trust,
or revocation status.

## 15. Related documentation

- [Generate and validate a CBOM](../how-to/generate-a-cbom.md)
- [CBOM conformance gate](../contributors/cbom-conformance.md)
- [JSON output](json-schema.md)
- [Failure categories](failure-categories.md)
