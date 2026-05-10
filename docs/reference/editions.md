# Reference: QuReddy editions

Side-by-side capability matrix for **QuReddy OSS** (this repository, free forever under Apache 2.0) and **BreachSAFE QuReddy Enterprise** (planned commercial product, P2 milestone). For the reasoning behind the split, see [explanation: OSS vs Enterprise](../explanation/oss-vs-enterprise.md). For the locked decision, see [ADR 0006](../contributors/adr/0006-oss-vs-enterprise-split.md).

## Status legend

- ✅ Available today
- 🛠️ Planned, scheduled milestone visible
- 🟦 Planned for the commercial product (P2)
- ❌ Never shipped in either edition (see "Never shipped" section)

## Capability matrix

### Scanners

| Capability | OSS | Enterprise |
|---|---|---|
| TLS scanner (X25519MLKEM768 hybrid + X25519 control) | ✅ MVP 0.1 | inherits OSS |
| Certificate scanner (chain, signatures, key sizes) | 🛠️ MVP 0.2 | inherits OSS |
| CBOM emission (CycloneDX 1.6) | 🛠️ MVP 0.3 | inherits OSS |
| SSH scanner (host keys, KEX algorithms) | 🛠️ MVP 0.4 | inherits OSS |
| Local crypto config scanner | 🛠️ MVP 0.5 | inherits OSS |
| Source-code scanner | 🛠️ MVP 0.6 | inherits OSS |
| Binary scanning (`.exe`, `.dll`, `.jar`, firmware) | ❌ | ❌ |

Every scanner ships in OSS. Enterprise inherits the full scanner suite — Enterprise's value-add is orchestration and integrations *around* the scanners, not different scanners.

### Output and reporting

| Capability | OSS | Enterprise |
|---|---|---|
| Rich console output | ✅ | inherits OSS |
| JSON output (locked `qureddy.scan.v1` schema) | ✅ | inherits OSS |
| CycloneDX 1.6 CBOM output | 🛠️ MVP 0.3 | inherits OSS |
| HTML output | 🛠️ post-MVP-0.3 | inherits OSS |
| CSV output | 🛠️ post-MVP-0.3 | inherits OSS |
| Markdown output | 🛠️ post-MVP-0.3 | inherits OSS |
| SARIF 2.1.0 output (GitHub Code Scanning) | 🛠️ (per issue #117) | inherits OSS |
| Compliance attestation reports (PDF, auditor-formatted) | ❌ | 🟦 PCI DSS 4.0, FFIEC, CMMC 2.0, etc. |
| Drift detection (compare scans over time) | ❌ | 🟦 |

### Operation

| Capability | OSS | Enterprise |
|---|---|---|
| Single-target CLI invocation | ✅ | inherits OSS |
| `--targets-file FILE` batch input | 🛠️ (per issue #118) | inherits OSS |
| Fleet/parallel scan orchestration (10,000+ endpoints) | ❌ | 🟦 |
| Persistent scan history storage | ❌ | 🟦 |
| Multi-account orchestration | ❌ | 🟦 |
| Scheduled scans / cron-equivalent | ❌ (cron is the answer) | 🟦 (SaaS scheduler with retry + alerting) |

### Cloud integration

| Capability | OSS | Enterprise |
|---|---|---|
| Scan TLS endpoints via cloud provider APIs (e.g. enumerate ELBs, scan all) | ❌ | 🟦 |
| AWS ACM certificate inventory + scan | ❌ | 🟦 |
| AWS KMS key inventory | ❌ | 🟦 |
| Azure Key Vault inventory | ❌ | 🟦 |
| GCP Cloud KMS inventory | ❌ | 🟦 |

OSS users with cloud assets can wire QuReddy into their own automation (the JSON output schema is stable). Enterprise provides the orchestration as a packaged offering.

### Integration

| Capability | OSS | Enterprise |
|---|---|---|
| Splunk HEC connector | ❌ | 🟦 |
| Datadog connector | ❌ | 🟦 |
| Elasticsearch connector | ❌ | 🟦 |
| Microsoft Sentinel connector | ❌ | 🟦 |
| ServiceNow connector | ❌ | 🟦 |
| Webhook delivery with delivery guarantees | ❌ | 🟦 |

OSS produces JSON; users wire it into anything that reads JSON. Enterprise productizes the connectors with replay, retry, and dead-letter handling.

### Multi-user / governance

| Capability | OSS | Enterprise |
|---|---|---|
| Single-user CLI | ✅ | inherits OSS |
| Multi-user SaaS dashboard | ❌ | 🟦 |
| SSO/SAML | ❌ | 🟦 |
| Role-based access control (RBAC) | ❌ | 🟦 |
| Audit log of who scanned what | ❌ (cron logs are the answer) | 🟦 |
| Team / org / project scoping | ❌ | 🟦 |

### Policy and rules

| Capability | OSS | Enterprise |
|---|---|---|
| Public NIST FIPS 203/204/205 alignment | ✅ MVP 0.1 onward | inherits OSS |
| NSA CNSA 2.0 mapping | 🛠️ MVP 0.3 | inherits OSS |
| PCI DSS 4.0 mapping | 🛠️ MVP 0.3 | inherits OSS |
| FFIEC / NCUA mapping | 🛠️ MVP 0.3 | inherits OSS |
| CMMC 2.0 mapping | 🛠️ MVP 0.3 | inherits OSS |
| Custom (private) rule packs for customer-specific compliance | ❌ | 🟦 |

Public-standard rule packs ship in OSS. Customer-specific rule packs that encode private compliance frameworks ship in Enterprise — they're sold alongside, not gated.

### Support and SLAs

| Capability | OSS | Enterprise |
|---|---|---|
| GitHub issue tracker | ✅ public, best-effort response | inherits + |
| Email support | ❌ | 🟦 dedicated channel |
| SLA on response time | ❌ | 🟦 |
| SLA on bug fix prioritization | ❌ | 🟦 |
| Direct security disclosure pipeline | ✅ per [`SECURITY.md`](../../SECURITY.md) | inherits + |
| Phone support | ❌ | 🟦 |

OSS gets the same security disclosure pipeline as Enterprise — security is not a gated feature. Routine support is where the line is.

### Project guarantees (both editions)

These hold in OSS and Enterprise — they're project-level commitments, not edition-level features:

| Guarantee | OSS | Enterprise |
|---|---|---|
| No telemetry, ever | ✅ | ✅ |
| Read-only operation | ✅ | ✅ |
| Local-first by default | ✅ | ✅ (cloud scans require explicit invocation) |
| Open data formats only (no proprietary binary formats) | ✅ | ✅ |
| Apache 2.0 OSS edition is permanent | ✅ locked via ADR 0006 | n/a (Enterprise is separate license) |

## Never shipped (explicit non-goals — neither edition)

These never ship, in either OSS or Enterprise:

- **Binary scanning** of compiled artifacts (`.exe`, `.dll`, `.jar`, `.apk`, firmware images). Crowded market (Veracode, BlackDuck, JFrog Xray, Snyk Container). Dual-use risk. Different problem domain.
- **Remediation** — QuReddy reports; humans (or their automation) act. Auto-remediation introduces too many trust-of-the-tool questions for a security scanner.
- **Continuous monitoring as an always-on agent** — cron + `qureddy scan tls` is the answer. Persistent agents have a wider attack surface than scheduled invocations.
- **AI/NHI (non-human identity) inventory** — that's a different product.
- **Telemetry** — no scan results, no usage stats, no error reports leave the scanner host without explicit operator action.
- **Support for EOL platforms** — Windows XP/7/8.1, RHEL 6, Ubuntu 16.04 and earlier are out of scope.

## How to choose

| If you... | Use |
|---|---|
| Want to scan a few endpoints from your laptop or a CI runner | **QuReddy OSS** |
| Need single-server compliance evidence for an audit | **QuReddy OSS** + your auditor's preferred report format |
| Are building automation around PQ readiness | **QuReddy OSS** (JSON output is stable, schema-locked) |
| Need to scan 10,000+ endpoints across multiple AWS accounts on a schedule, with results in Splunk | **BreachSAFE QuReddy Enterprise** (planned, P2) |
| Need a multi-user dashboard with RBAC and SAML | **BreachSAFE QuReddy Enterprise** (planned, P2) |
| Need formatted auditor-ready PCI DSS attestation PDFs | **BreachSAFE QuReddy Enterprise** (planned, P2) — or generate them yourself from OSS JSON output |
| Need binary scanning of `.exe`/`.dll`/`.jar` | Use [`syft`](https://github.com/anchore/syft), [`trivy`](https://github.com/aquasecurity/trivy), or BlackDuck — not QuReddy, in either edition |
| Need vulnerability scanning of TLS configurations (Heartbleed, BEAST, etc.) | Use [`sslyze`](https://github.com/nabla-c0d3/sslyze) or [`testssl.sh`](https://testssl.sh) — not QuReddy, in either edition |

## Related

- [Explanation: Why QuReddy is open-core](../explanation/oss-vs-enterprise.md) — the reasoning behind this matrix
- [ADR 0006 — OSS vs Enterprise split](../contributors/adr/0006-oss-vs-enterprise-split.md) — the locked decision
- [Reference: Project milestones](milestones.md) — when P2 (Enterprise) is on the roadmap
- [`SECURITY.md`](../../SECURITY.md) — security disclosure pipeline (both editions)
