<!--
SPDX-FileCopyrightText: 2026 BreachSAFE
SPDX-License-Identifier: Apache-2.0
-->

# Markdown output architecture

QuReddy emits two retrieval-oriented Markdown documents beside its machine
artifacts. Each document has one source of truth and a stable structure for
operators and document-indexing systems.

## Contents

1. [Output map](#1-output-map)
2. [Scan document](#2-scan-document)
3. [CBOM document](#3-cbom-document)
4. [Bundle](#4-bundle)
5. [Boundaries](#5-boundaries)
6. [Acceptance](#6-acceptance)

## 1. Output map

```text
                         ScanResult
                      ┌──────┴──────┐
                      │             │
                      ▼             ▼
              native scan.md   CBOM builder
                                    │
                                    ▼
                           final CycloneDX payload
                              ┌─────┴─────┐
                              ▼           ▼
                       scan.cdx.json  native cbom.md
```

The scan and CBOM documents are related but different projections. The scan
document describes the run and its observations. The CBOM document describes
CycloneDX assets, properties, evidence, annotations, and relationships.

## 2. Scan document

`scan.md` is created directly from the typed `ScanResult` model. Its sections
are stable retrieval boundaries:

```text
# QuReddy Scan
## Run
## Target
## Dependencies
## Assets
## Findings
## Evidence
## Summary
```

Records use deterministic field paths such as:

```text
- id: finding-123
- rule_id: tls.transport.weak
- severity: high
- evidence_ids[0]: evidence-456
```

Repeated records remain separate headings. Empty collections are explicit. A
value containing line breaks is normalized to one Markdown line so observed
data cannot create an unintended heading or list item.

## 3. CBOM document

`cbom.md` is created from the final validated CycloneDX payload returned by the
CBOM builder. The builder is called once; the same payload is serialized to
`scan.cdx.json` and passed to the Markdown renderer.

```text
# QuReddy CBOM
## Metadata
## Components
### Component 1
## Dependencies
### Dependency 1
## Annotations
### Annotation 1
## Additional fields
```

The renderer recursively formats mappings and arrays. It does not contain TLS,
SSH, IKE, wallet, or artifact-specific rules. New CycloneDX fields appear under
their field paths, including fields the current renderer does not know by name.

## 4. Bundle

An output directory contains:

```text
RUN_DIR/
├── scan.json
├── scan.jsonl
├── scan.cdx.json
├── scan.rich.txt
├── scan.md
├── cbom.md
└── certificate.pem        # only when certificate evidence exists
```

`scan.json` and `scan.cdx.json` remain the machine-authoritative artifacts.
`scan.md` and `cbom.md` are portable retrieval views. The CLI does not upload
files or call RAGFlow.

## 5. Boundaries

```text
scanner ──▶ ScanResult ──▶ scan.md
                     └──▶ CBOM builder ──▶ scan.cdx.json + cbom.md
```

- The scan renderer reads the typed `ScanResult`.
- The CBOM renderer reads the final validated CycloneDX payload.
- The CBOM builder owns CycloneDX semantics and is not duplicated in Markdown.
- No renderer invokes a scanner, subprocess, network service, or document indexer.
- Raw certificate PEM remains governed by the existing certificate artifact
  contract rather than being copied into Markdown.

## 6. Acceptance

- `scan.md` contains every serialized `ScanResult` top-level field.
- `cbom.md` contains metadata, components, properties, evidence, dependencies,
  annotations, and unknown future fields.
- Repeated records remain distinct and ordered.
- Empty and partial results are explicit.
- `scan.cdx.json` remains valid CycloneDX and is generated once.
- The native renderer uses the same source data as the machine artifacts.
