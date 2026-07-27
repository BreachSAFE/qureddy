# OSS and Enterprise boundary

QuReddy OSS is the Apache 2.0 scanner in this repository. The accepted product
boundary keeps cryptographic observation, interpretation, and standard output
formats in OSS. A future Enterprise product may add operated infrastructure
and organization-scale workflows.

## Contents

- [Boundary rule](#boundary-rule)
- [OSS responsibilities](#oss-responsibilities)
- [Planned Enterprise responsibilities](#planned-enterprise-responsibilities)
- [Why the boundary exists](#why-the-boundary-exists)
- [How to classify a contribution](#how-to-classify-a-contribution)
- [Current evidence](#current-evidence)
- [Related documentation](#related-documentation)

## Boundary rule

The decision in [ADR 0006](../contributors/adr/0006-oss-vs-enterprise-split.md)
uses this division:

```text
OSS: collect and interpret cryptographic evidence in standard formats
Enterprise: operate, persist, orchestrate, and integrate that evidence at scale
```

This is a product boundary. It does not make planned Enterprise behavior a
shipped feature.

## OSS responsibilities

QuReddy OSS owns:

- TLS and SSH endpoint scanners;
- target parsing and bounded collection;
- readiness rules and explicit unknown states;
- Rich and `qureddy.scan.v1` JSON output;
- CycloneDX 1.7 CBOM output;
- public schemas, fixtures, conformance tests, and release evidence;
- a single-target command line interface;
- Apache 2.0 source and standard artifacts.

Future scanners that observe cryptographic posture belong in OSS when they fit
the repository's accepted scope.

## Planned Enterprise responsibilities

The Enterprise boundary may include:

- hosted multi-tenant operation;
- fleet and cloud account orchestration;
- persistent history and drift workflows;
- identity, access control, and organization policy;
- managed SIEM and ticketing integrations;
- service-level support;
- operated compliance reporting.

No item in this list is claimed as shipped by this repository.

## Why the boundary exists

Observation rules and standard artifact contracts benefit from public review,
reproducible fixtures, and independent validation. Those properties make the
scanner useful to individual operators and downstream consumers.

Hosted infrastructure introduces different concerns: credentials, tenancy,
durable storage, availability, integration maintenance, support, and
operations. Keeping that work outside the scanner prevents service concerns
from changing the evidence contract.

## How to classify a contribution

| Proposal | Boundary | Reason |
| --- | --- | --- |
| Parse another standard cryptographic observation | OSS | Scanner evidence |
| Add a standards-conformant CBOM field | OSS | Artifact contract |
| Add a bounded endpoint scanner | OSS | Collection capability |
| Add a small local batch input | OSS candidate | Command line operation without hosted state |
| Enumerate a customer's cloud account with credentials | Enterprise candidate | Credentialed orchestration |
| Store tenant scan history | Enterprise candidate | Multi-tenant persistence |
| Deliver results to a managed SIEM connector | Enterprise candidate | Operated integration |

Ambiguous proposals require an issue and an architecture decision before
implementation. A label change does not create the required security,
tenancy, persistence, or evidence semantics.

## Current evidence

The shipped OSS artifact provides TLS, SSH, JSON, and CycloneDX 1.7 CBOM
surfaces. The repository does not contain an Enterprise service, SaaS control
plane, fleet database, cloud credential workflow, or managed connector.

See the [edition matrix](../reference/editions.md) for the exact status of each
capability.

## Related documentation

- [Edition matrix](../reference/editions.md)
- [ADR 0006](../contributors/adr/0006-oss-vs-enterprise-split.md)
- [Milestones](../reference/milestones.md)
- [Evidence honesty](evidence-honesty.md)
