# Edition reference

This matrix separates the shipped Apache 2.0 QuReddy OSS artifact from the
planned BreachSAFE QuReddy Enterprise product. Planned entries are not present
in this repository.

## Contents

- [Status legend](#status-legend)
- [Scanner and output matrix](#scanner-and-output-matrix)
- [Operation matrix](#operation-matrix)
- [Security and support matrix](#security-and-support-matrix)
- [Explicit non-goals](#explicit-non-goals)
- [Choose a surface](#choose-a-surface)
- [Related documentation](#related-documentation)

## Status legend

| Status | Meaning |
| --- | --- |
| Shipped | Present in the installed 0.2.0 artifact |
| Planned | Recorded intent without a delivered implementation |
| Not provided | Explicitly outside that edition |

## Scanner and output matrix

| Capability | QuReddy OSS | Enterprise |
| --- | --- | --- |
| TLS endpoint scanner | Shipped | Inherits OSS if delivered |
| SSH and SFTP endpoint scanner | Shipped | Inherits OSS if delivered |
| Leaf certificate signature observation | Shipped in TLS scan | Inherits OSS if delivered |
| Full certificate chain and key-size analysis | Planned OSS | Inherits OSS if delivered |
| Local crypto configuration scanner | Planned OSS | Inherits OSS if delivered |
| Source-code scanner | Planned OSS | Inherits OSS if delivered |
| Rich terminal output | Shipped | Inherits OSS if delivered |
| `qureddy.scan.v1` JSON | Shipped | Inherits OSS if delivered |
| CycloneDX 1.7 CBOM | Shipped | Inherits OSS if delivered |
| HTML, CSV, Markdown, or SARIF output | Planned OSS; no release commitment | Inherits OSS if delivered |

The Enterprise column states the accepted boundary, not an available product
surface.

## Operation matrix

| Capability | QuReddy OSS | Enterprise |
| --- | --- | --- |
| One target per command | Shipped | Inherits OSS if delivered |
| Local scheduled invocation | Use an external scheduler | May provide managed scheduling |
| Local file loop or caller orchestration | Operator owned | May provide fleet orchestration |
| Persistent scan history | Not provided | Planned |
| Multi-tenant service | Not provided | Planned |
| Cloud account discovery | Not provided | Planned |
| Managed SIEM or ticketing connectors | Not provided | Planned |
| Organization identity and access control | Not provided | Planned |

## Security and support matrix

| Capability | QuReddy OSS | Enterprise |
| --- | --- | --- |
| Apache 2.0 scanner source | Shipped | Uses OSS scanner if delivered |
| Public issue tracker | Shipped, best effort | May add supported channels |
| Private vulnerability reporting | Shipped through `SECURITY.md` | Must preserve at least the same path |
| Telemetry from the OSS scanner | None | Any future service collection requires a separate disclosed contract |
| Support SLA | Not provided | Planned |
| Hosted compliance conclusions | Not provided | Planned |

## Explicit non-goals

Neither edition is planned to use QuReddy for:

- binary and firmware scanning;
- automatic target remediation;
- endpoint exploitation;
- general TLS vulnerability assessment;
- hidden telemetry;
- support for end-of-life operating systems.

QuReddy OSS does not become a hosted service by adding a Docker image. Delivery
format and operated product semantics are separate concerns.

## Choose a surface

| Need | Current answer |
| --- | --- |
| Inspect one TLS or SSH endpoint | QuReddy OSS |
| Produce JSON or CycloneDX 1.7 evidence | QuReddy OSS |
| Run from a local CI job | QuReddy OSS |
| Scan a list today | Invoke the OSS command once per target and preserve each exit code |
| Operate a multi-tenant fleet service | Not shipped |
| Store historical posture and drift | Not shipped |
| Receive a managed compliance report | Not shipped |
| Scan binaries or firmware | Use a dedicated binary or software composition tool |
| Test TLS vulnerabilities | Use a dedicated TLS security scanner |

## Related documentation

- [OSS and Enterprise boundary](../explanation/oss-vs-enterprise.md)
- [Project milestones](milestones.md)
- [Security policy](../../SECURITY.md)
