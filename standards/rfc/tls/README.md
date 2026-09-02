<!--
SPDX-FileCopyrightText: 2026 BreachSAFE
SPDX-License-Identifier: Apache-2.0
-->
# TLS weak-cipher RFC corpus

Primary-source RFC text that backs QuReddy's cryptographic ratings. Each rating in the
crypto registry (issue #708) cites a source in this corpus by digest, so a reviewer can
re-check the claim against the vendored text rather than against memory.

## Contents

1. [Why this exists](#1-why-this-exists)
2. [Manifest](#2-manifest)
3. [Provenance and integrity](#3-provenance-and-integrity)
4. [Licensing](#4-licensing)

## 1. Why this exists

The registry records a weak verdict only when it can cite the source that assigns it. That
requires the source to be present and pinned, the way `breachsafe-standards/standards/rfc/iana-ike/`
vendors the IKE corpus. These seven RFCs are the TLS weak-cipher sources: the IANA `Recommended`
column structure, the forward-secrecy recommendations, and the deprecations for TLS 1.0/1.1,
MD5/SHA-1, DES/IDEA, and RC4.

## 2. Manifest

Retrieved 2026-09-02 from `https://www.rfc-editor.org/rfc/rfc<n>.txt`, verbatim and unmodified.

| RFC | Title (short) | Assigns | SHA-256 |
|---|---|---|---|
| 5469 | DES/IDEA cipher suites | deprecates DES and IDEA suites | `41ff03084d550cd6bdc187712521e60e48f3171f56c8a9247ddb3211650bbaca` |
| 7465 | Prohibiting RC4 | RC4 prohibited | `0c619db38176f199f739dc696a2d3faabbe658ee82d59621c6d040d0b7cce2dd` |
| 8996 | Deprecating TLS 1.0/1.1 | TLS 1.0 and 1.1 deprecated | `a8250792df7fc533328f2021dbdcce847bbdfbc703de89a93e18ce165d4b8d14` |
| 9155 | Deprecating MD5/SHA-1 in TLS 1.2 | MD5 and SHA-1 signature hashes deprecated | `87c859e927ab6bbf245f4f3cd909852b28c5d253e2305cbdd715e93aa79db7d2` |
| 9325 | Recommendations for Secure Use of TLS/DTLS (BCP 195) | forward-secrecy requirement, MUST-NOT suites | `e3475381d056bde1eed65252954cce68250168454387f6799b38660806f215bc` |
| 9847 | IANA Registry Updates for TLS and DTLS | the `Y`/`N`/`D` Recommended structure | `5f26e46fdda1b04860afef42b8e3162d861fdf86dad6ec200cd21fff9f279c6f` |
| 10015 | Obsolete TLS 1.2 key-exchange classifications | classical key-exchange status | `1cc53f068b7c02e7c49c77816d16d6453b6f094762fb16e361d358da96ac1086` |

## 3. Provenance and integrity

Verify any file against its manifest digest:

```bash
shasum -a 256 standards/rfc/tls/rfc7465.txt
```

The registry pins these same digests in its `sources` records. A registry `source` marked
`verified: true` means its digest equals the file here. RFC 7465 and RFC 10015 digests were
cross-checked against an independent fetch and matched.

## 4. Licensing

The RFC text is copyright the IETF Trust and the document authors, redistributed under the IETF
Trust Legal Provisions (BCP 78), which permit full unmodified reproduction. See
`LICENSES/LicenseRef-IETF-Trust.txt`. Each file's own Copyright Notice is preserved. This README
is BreachSAFE-authored under Apache-2.0.
