# Security Policy

[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow?style=flat-square)](https://github.com/PyCQA/bandit)
[![pip-audit](https://img.shields.io/badge/dep%20scan-pip--audit-blue?style=flat-square)](https://pypi.org/project/pip-audit/)
[![Secret Scan: gitleaks](https://img.shields.io/badge/secret%20scan-gitleaks-red?style=flat-square)](https://github.com/gitleaks/gitleaks)
[![SPDX: reuse](https://img.shields.io/badge/license%20headers-reuse-green?style=flat-square)](https://reuse.software/)
[![OpenSSF Best Practices](https://img.shields.io/badge/OpenSSF-passing%20%28target%20MVP%200.6%29-yellow?style=flat-square)](https://www.bestpractices.dev/)
[![Disclosure SLA](https://img.shields.io/badge/disclosure%20SLA-5%20business%20days-brightgreen?style=flat-square)](#response-sla)

QuReddy is a security tool. We take vulnerability reports seriously.

## Supported Versions

Pre-MVP. No releases yet. Once releases ship:

| Version | Supported |
|---|---|
| `main` (development) | Yes |
| latest tagged release | Yes |
| any prior release | No |

We do not backport security fixes to prior tagged releases. Upgrade to the latest release.

## Reporting a Vulnerability

**Do not file a public GitHub issue for vulnerabilities.**

Use **GitHub Security Advisories** at https://github.com/paul007ex/qureddy/security/advisories/new to report privately. The repository maintainer is automatically notified.

If you cannot use GitHub Security Advisories, email the maintainer; the contact is in the GitHub profile of the project owner.

### What to include

- A description of the vulnerability and its impact
- Reproduction steps or proof-of-concept
- The version (commit SHA or release tag) you tested against
- Your contact info for follow-up

### Response SLA

We commit to:

- **Acknowledgement within 5 business days** of receipt
- **Initial assessment within 10 business days** (severity classification, fix planning)
- **Fix or disclosure timeline within 30 business days** for critical and high severity
- **Coordinated disclosure** at a date you and the maintainer agree on

If we miss any of these, the maintainer has failed the OpenSSF Best Practices criterion. You are entitled to escalate by re-opening the report or going public with the details and disclosure timeline.

## Disclosure Policy

We follow **coordinated disclosure**:

1. Reporter sends a private report.
2. Maintainer acknowledges, classifies, and proposes a fix and disclosure date.
3. Both parties agree on timing.
4. Fix is developed in a private fork.
5. On the agreed date, the fix is published, a GitHub Security Advisory is posted with CVE assignment if eligible, and the reporter is credited (unless they request otherwise).

We will not retaliate against reporters acting in good faith. We will not pursue legal action against researchers who follow this disclosure policy.

## Scope

In scope:
- The QuReddy CLI and Python package (`breachsafe-qureddy`)
- Distributed Docker images (when v1.0 ships)
- The 7-phase CI pipeline if it produces unsigned or compromised artifacts
- Documentation that misleads users about cryptographic posture

Out of scope:
- Vulnerabilities in dependencies that have been disclosed and patched upstream — file with the upstream project
- Theoretical issues without a working PoC
- Social engineering of contributors
- Denial of service against the QuReddy maintainers

## Security Hygiene Commitments

QuReddy commits to:

- **No `verify=False`, `shell=True`, `eval`/`exec`, or `pickle.loads`** in shipped code (`docs/CODING_RULES.md` §26 security bar)
- **No logging of secrets, full PEMs, or full subprocess output** (`docs/CODING_RULES.md` Rule 8.5)
- **No insecure shortcuts even when requested by users or AI agents** (`docs/CODING_RULES.md` Rule 26.13)
- **`pip-audit` runs as a per-PR Tier 2 gate** to catch known vulnerable dependencies
- **`bandit` runs at MEDIUM threshold as a per-PR Tier 1 gate** to catch Python security footguns
- **Secret scanning (`gitleaks` or `trufflehog`)** on every PR diff
- **SPDX license headers verified by `reuse lint`** on every source file
- **Branch protection on `main`** — no direct pushes, all changes go through reviewed PRs
- **OpenSSF Best Practices Badge** — passing tier by MVP 0.6, silver by v1.0
- **Sigstore-signed release artifacts** at v1.0 with SLSA provenance

## Security Exceptions

Time-bounded security exceptions are documented in `docs/SECURITY_EXCEPTIONS.md` (when first exception is recorded). Format:

```
SECURITY EXCEPTION ACCEPTED: <rule>, because <reason>, expires <date or issue link>
```

The release workflow checks for expired exceptions and fails if any have lapsed. Permanent silent exceptions do not exist.
