# Security Policy

[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow?style=flat-square)](https://github.com/PyCQA/bandit)
[![pip-audit](https://img.shields.io/badge/dep%20scan-pip--audit-blue?style=flat-square)](https://pypi.org/project/pip-audit/)
[![Secret Scan: gitleaks](https://img.shields.io/badge/secret%20scan-gitleaks-red?style=flat-square)](https://github.com/gitleaks/gitleaks)
[![SPDX: reuse](https://img.shields.io/badge/license%20headers-reuse-green?style=flat-square)](https://reuse.software/)
[![OpenSSF Best Practices](https://img.shields.io/badge/OpenSSF-passing-yellow?style=flat-square)](https://www.bestpractices.dev/)
[![Disclosure SLA](https://img.shields.io/badge/disclosure%20SLA-5%20business%20days-brightgreen?style=flat-square)](#3-response-targets)

QuReddy is a security tool. We take vulnerability reports seriously.

## Contents

1. [Supported versions](#1-supported-versions)
2. [Report a vulnerability](#2-report-a-vulnerability)
3. [Response targets](#3-response-targets)
4. [Disclosure policy](#4-disclosure-policy)
5. [Scope](#5-scope)
6. [Enforced security checks](#6-enforced-security-checks)
7. [Release controls](#7-release-controls)
8. [Security exceptions](#8-security-exceptions)

## 1. Supported Versions

| Version | Supported |
|---|---|
| `main` (development) | Yes |
| `0.2.x` release candidates and latest published `0.2.x` | Yes |
| `0.1.x` and earlier | No |

Security fixes target `main` and the latest `0.2.x` release. No backport
commitment exists for earlier versions.

## 2. Report a vulnerability

**Do not file a public GitHub issue for vulnerabilities.**

Use **GitHub Security Advisories** at https://github.com/breachsafe/qureddy/security/advisories/new to report privately. The repository maintainer is automatically notified.

If you cannot use GitHub Security Advisories, email the maintainer; the contact is in the GitHub profile of the project owner.

### What to include

- A description of the vulnerability and its impact
- Reproduction steps or proof-of-concept
- The version (commit SHA or release tag) you tested against
- Your contact info for follow-up

## 3. Response targets

We commit to:

- **Acknowledgement within 5 business days** of receipt
- **Initial assessment within 10 business days** (severity classification, fix planning)
- **Fix or disclosure timeline within 30 business days** for critical and high severity
- **Coordinated disclosure** at a date you and the maintainer agree on

If we miss any of these, the maintainer has failed the OpenSSF Best Practices criterion. You are entitled to escalate by re-opening the report or going public with the details and disclosure timeline.

## 4. Disclosure Policy

We follow **coordinated disclosure**:

1. Reporter sends a private report.
2. Maintainer acknowledges, classifies, and proposes a fix and disclosure date.
3. Both parties agree on timing.
4. Fix is developed in a private fork.
5. On the agreed date, the fix is published, a GitHub Security Advisory is posted with CVE assignment if eligible, and the reporter is credited (unless they request otherwise).

We will not retaliate against reporters acting in good faith. We will not pursue legal action against researchers who follow this disclosure policy.

## 5. Scope

In scope:

- The QuReddy CLI and Python package (`breachsafe-qureddy`)
- Distributed Docker images when published
- The 7-phase CI pipeline if it produces unsigned or compromised artifacts
- Documentation that misleads users about cryptographic posture

Out of scope:

- Vulnerabilities in dependencies that have been disclosed and patched upstream; file with the upstream project
- Theoretical issues without a working PoC
- Social engineering of contributors
- Denial of service against the QuReddy maintainers

## 6. Enforced security checks

The repository enforces:

- **No `verify=False`, `shell=True`, `eval`/`exec`, or `pickle.loads`** in shipped code (`docs/contributors/coding-rules.md` §26 security bar)
- **No logging of secrets, full PEMs, or full subprocess output** (`docs/contributors/coding-rules.md` Rule 8.5)
- **No insecure shortcuts even when requested by users or AI agents** (`docs/contributors/coding-rules.md` Rule 26.13)
- **`pip-audit`** against the installed runtime dependency path with no ignored advisories
- **`bandit`** at the repository's configured threshold
- **Gitleaks** over full Git history in the local release gate
- **`reuse lint`** for SPDX and license metadata
- **CycloneDX 1.7 final-byte conformance** against pinned schemas, an independent validator, and semantic checks
- **Exact artifact inspection and clean installation** for the wheel and source distribution

## 7. Release controls

OpenSSF badge advancement, Sigstore signatures, SLSA provenance, Docker
publication, and hosted release settings require externally verifiable
artifacts or repository settings before they are treated as active controls.

## 8. Security Exceptions

Time-bounded security exceptions are documented in `docs/SECURITY_EXCEPTIONS.md` (when first exception is recorded). Format:

```
SECURITY EXCEPTION ACCEPTED: <rule>, because <reason>, expires <date or issue link>
```

No exception exists until it is recorded in that file and reviewed in the
pull request that introduces it. Automated expiry is not currently enforced;
permanent silent exceptions do not exist.
