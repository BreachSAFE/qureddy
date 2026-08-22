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
7. [Findings, evidence, and verdicts](#7-findings-evidence-and-verdicts)
8. [Relationships](#8-relationships)
9. [Scan status](#9-scan-status)
10. [Stable references and volatile fields](#10-stable-references-and-volatile-fields)
11. [Positive observation rule](#11-positive-observation-rule)
12. [Certificate fields](#12-certificate-fields)
13. [Reproducibility](#13-reproducibility)
14. [Validation contract](#14-validation-contract)
15. [Evidence limits](#15-evidence-limits)
16. [Related documentation](#16-related-documentation)

## 1. Interoperability

The document is native CycloneDX throughout (see
[CBOM design](../explanation/cbom-design.md)):

1. Crypto inventory. Observed algorithms, protocols, and the certificate are
   real CycloneDX `components` with native `cryptoProperties`
   (`algorithmProperties`/`protocolProperties`/`certificateProperties`) and a
   native `provides` graph. Any CycloneDX 1.7, crypto-aware tool (for example IBM
   CBOMkit or Dependency-Track's crypto support) understands this layer, including
   the post-quantum posture, with no CVE identifiers required.
2. Findings and evidence, also native (0.2.23, #287). Each observation is attached
   to the asset it describes as `component.evidence.occurrences`; each finding is a
   top-level `annotation` whose `subjects` link to that asset, carrying the title and
   full description (including standards citations); each finding's machine verdict
   (readiness, severity, rule id) is a queryable `qureddy:`-namespaced property on the
   subject component.
3. A small `qureddy:`-namespaced `metadata.properties` layer for scan, target, and
   tool provenance only.

Consequences: the document parses in every CycloneDX 1.7 tool; the inventory,
evidence occurrences, and annotations are natively understood; a QuReddy-aware
consumer such as Qurum additionally reads the verdict properties as fields rather
than parsing prose. `properties`/`annotations`/`occurrences` are all valid
CycloneDX, so a tool that ignores the `qureddy:` verdict keys never fails
ingestion. Because `cryptoProperties` is CycloneDX 1.6+ and this document is 1.7,
tooling pinned to 1.6 or earlier will not accept it. The full scan report is also
available in `--format json`; Prowler and TAO consume that report
(`qureddy.scan.v1`), not the CBOM.

Earlier releases (through 0.2.22) instead carried findings and evidence as flat
`qureddy:finding.NN.*` / `qureddy:evidence.NN.*` `metadata.properties`; 0.2.23 replaced
that with the native structures above (#287), so a consumer that keyed on those flat
property names must migrate to the annotations, occurrences, and verdict properties.

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

Beyond their `cryptoProperties`, asset components also carry the observations and
verdict that concern them, in native CycloneDX fields:

- `evidence.occurrences` — one entry per probe observation of the asset, with the
  probe provenance in the occurrence `additionalContext` string.
- `qureddy:readiness`, `qureddy:severity`, `qureddy:rule_id` component
  `properties` — the machine verdict for the finding whose subject is this asset.

Findings themselves are top-level `annotations` that link back to the asset by
`bom-ref`. See [findings, evidence, and verdicts](#7-findings-evidence-and-verdicts).

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

See [certificate fields](#12-certificate-fields) for the populated properties and
limits.

## 7. Findings, evidence, and verdicts

Since 0.2.23 (#287) QuReddy's interpretation and provenance ride in native
CycloneDX structures rather than a flat `qureddy:` property namespace.

### Evidence as occurrences

Each observation is attached to the crypto asset it describes as a
`component.evidence.occurrences` entry. The probe provenance — observation type,
role, expected group, return code, the full `command_sha256`, and duration —
rides in the occurrence `additionalContext` string.

### Findings as annotations

Each finding is a top-level CycloneDX `annotation`:

| Field | Contract |
| --- | --- |
| `subjects` | `bom-ref` of the crypto asset the finding concerns |
| `annotator` | the QuReddy tool component (`tool/qureddy`) |
| `timestamp` | the real scan completion time (`completed_at`); pinned to `1970-01-01T00:00:00+00:00` under `--reproducible` |
| `text` | the finding title plus its full description, including any standards citations |

Annotation `bom-ref` values are unique, and every `subjects` entry resolves to a
component in the document. Both are enforced by the semantic checks
([validation contract](#14-validation-contract)).

### Verdict as component properties

Each finding's machine verdict rides on its subject component as `qureddy:readiness`,
`qureddy:severity`, and `qureddy:rule_id` `properties`, so a consumer reads the
verdict as queryable fields rather than parsing the annotation prose.

### Run-level provenance

Scan, target, and tool provenance (`qureddy:scan.*`, `qureddy:target.*`,
`qureddy:openssl.*`) stay in `metadata.properties`, including the run-level
`qureddy:scan.readiness` and `qureddy:scan.status` (see [scan status](#9-scan-status)).

Releases through 0.2.22 instead carried findings and evidence as flat
`qureddy:finding.NN.*` / `qureddy:evidence.NN.*` `metadata.properties`; a consumer
that keyed on those names must migrate to the annotations, occurrences, and verdict
properties above.

## 8. Relationships

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

## 9. Scan status

CycloneDX metadata properties preserve the execution state:

| Property | Presence | Meaning |
| --- | --- | --- |
| `qureddy:scan.status` | always | `completed` or the top-level failure category |
| `qureddy:scan.failure_category` | on typed failure | Canonical failure category |

A schema-valid sparse CBOM is not proof of a successful scan. Consumers must
read these properties and preserve failure or unknown states.

## 10. Stable references and volatile fields

The endpoint and component `bom-ref` values are deterministic for the same
observations. Component and relationship order is deterministic.

CycloneDX requires run-level identity and time fields that change:

- top-level `serialNumber`;
- `metadata.timestamp`;
- each finding annotation `timestamp` (the real scan completion time).

Conformance tests normalize those fields before comparing repeated renders. All
remaining bytes must be identical for the same fixture.

## 11. Positive observation rule

CBOM inventory includes evidence with observation type:

```text
negotiated
offered
observed
```

`inferred` and `not_testable` evidence does not create cryptographic asset
components. Missing evidence remains missing instead of becoming a favorable
asset claim.

## 12. Certificate fields

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

## 13. Reproducibility

By default the CBOM carries per-run identity (a CycloneDX `serialNumber` and
`metadata.timestamp`, each finding annotation `timestamp`, plus `qureddy:scan.id`
and the scan start/finish times), so two runs of the same scan produce different
bytes. Pass `--reproducible` to omit those fields and pin every annotation
`timestamp` to the Unix epoch (`1970-01-01T00:00:00+00:00`): the same observed
crypto then yields byte- and digest-identical output for content addressing. The
crypto inventory, ordering, and values are identical either way.

## 14. Validation contract

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
- duplicate `bom-ref` values, including duplicate annotation `bom-ref` values;
- dangling `dependsOn`/`provides`, `signatureAlgorithmRef`, and cipher-suite
  algorithm references;
- an annotation `subjects` entry that does not resolve to a component in the
  document;
- secret-like fields or material.

The fixture matrix contains positive and negative cases with provenance
sidecars. The installed console canary validates successful and failed scan
bytes and render determinism.

## 15. Evidence limits

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

## 16. Related documentation

- [Generate and validate a CBOM](../how-to/generate-a-cbom.md)
- [CBOM conformance gate](../contributors/cbom-conformance.md)
- [JSON output](json-schema.md)
- [Failure categories](failure-categories.md)
