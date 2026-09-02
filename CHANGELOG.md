# Changelog

[![Status: Alpha](https://img.shields.io/badge/status-alpha-blue?style=flat-square)](https://github.com/BreachSAFE/qureddy)
[![Latest release](https://img.shields.io/github/v/release/BreachSAFE/qureddy?display_name=tag&style=flat-square)](https://github.com/BreachSAFE/qureddy/releases/latest)
[![Keep a Changelog](https://img.shields.io/badge/keep%20a%20changelog-1.1.0-orange?style=flat-square)](https://keepachangelog.com/en/1.1.0/)
[![PEP 440](https://img.shields.io/badge/versioning-PEP%20440-blue?style=flat-square)](https://peps.python.org/pep-0440/)

All notable user-visible changes to QuReddy are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and package
versions follow [PEP 440](https://peps.python.org/pep-0440/).

## Contents

1. [Unreleased](#unreleased)
2. [0.9.6](#096---2026-09-02)
3. [0.9.5](#095---2026-09-02)
4. [0.9.4](#094---2026-09-02)
5. [0.9.3](#093---2026-09-01)
6. [0.9.2](#092---2026-09-01)
7. [0.9.1](#091---2026-08-31)
8. [0.9.0.10](#09010---2026-08-30)
9. [0.9.0.9](#0909---2026-08-26)
10. [0.9.0.8](#0908---2026-08-26)
11. [0.9.0.7](#0907---2026-08-26)
12. [0.9.0.6](#0906---2026-08-26)
13. [0.9.0.5](#0905---2026-08-26)
14. [0.9.0.4](#0904---2026-08-26)
15. [0.9.0.3](#0903---2026-08-25)
16. [0.9.0.2](#0902---2026-08-25)
17. [0.9.0.1](#0901---2026-08-24)
18. [0.9.0.0](#0900---2026-08-24)

## Unreleased

### Fixed

- Keep `--json-logs` valid JSON Lines when third-party libraries emit records through
  standard-library logging ([issue #670](https://github.com/BreachSAFE/qureddy/issues/670),
  [PR #695](https://github.com/BreachSAFE/qureddy/pull/695)).

## [0.9.6] - 2026-09-02

### Fixed

- Restore the source checkout in the release-only container manifest job so signature
  verification and multi-registry publication can complete
  ([issue #667](https://github.com/BreachSAFE/qureddy/issues/667),
  [PR #668](https://github.com/BreachSAFE/qureddy/pull/668)).
- Keep negotiated or observed post-quantum protection in the top-level readiness verdict
  while reporting deprecated protocols and weak algorithms on the independent hygiene axis
  ([issue #663](https://github.com/BreachSAFE/qureddy/issues/663),
  [PR #677](https://github.com/BreachSAFE/qureddy/pull/677)).

## [0.9.5] - 2026-09-02

### Fixed

- Retry Docker Hub signature verification after staging a manifest, while preserving
  fail-closed issuer and identity checks, so registry propagation delay does not fail an
  otherwise valid release ([issue #659](https://github.com/BreachSAFE/qureddy/issues/659),
  [PR #660](https://github.com/BreachSAFE/qureddy/pull/660)).
- Label an SSH key exchange as post-quantum hybrid in Rich output only when the canonical
  classifier confirms a hybrid algorithm
  ([issue #534](https://github.com/BreachSAFE/qureddy/issues/534),
  [PR #661](https://github.com/BreachSAFE/qureddy/pull/661)).
- Preserve bracketed IPv6 targets, including zone identifiers, in the Rich verdict title
  ([issue #495](https://github.com/BreachSAFE/qureddy/issues/495),
  [PR #662](https://github.com/BreachSAFE/qureddy/pull/662)).
- Omit the unsupported RSA-4096 `classicalSecurityLevel` from CBOM instead of attributing
  an interpolated 152-bit value to NIST SP 800-57 Table 2
  ([issue #531](https://github.com/BreachSAFE/qureddy/issues/531),
  [PR #664](https://github.com/BreachSAFE/qureddy/pull/664)).
- Document the distinct verbosity levels accurately: `-vv` emits debug subprocess
  boundaries, while `-vvv` adds exact commands to Rich output and internal-error tracebacks
  ([issue #498](https://github.com/BreachSAFE/qureddy/issues/498),
  [PR #665](https://github.com/BreachSAFE/qureddy/pull/665)).

## [0.9.4] - 2026-09-02

### Added

- Emit typed leaf-certificate subject, issuer, validity, serial, signature, and
  public-key facts in JSON certificate evidence
  ([issue #640](https://github.com/BreachSAFE/qureddy/issues/640),
  [PR #655](https://github.com/BreachSAFE/qureddy/pull/655)).
- Record the observed TLS ephemeral public-key size in JSON and as native CycloneDX
  related cryptographic material ([issue #638](https://github.com/BreachSAFE/qureddy/issues/638),
  [PR #654](https://github.com/BreachSAFE/qureddy/pull/654)).

### Fixed

- Preserve the live TLS CertificateVerify signature and hash in JSON and emit the
  signature as a distinct CBOM algorithm observation
  ([issue #637](https://github.com/BreachSAFE/qureddy/issues/637),
  [PR #654](https://github.com/BreachSAFE/qureddy/pull/654)).

## [0.9.3] - 2026-09-01

### Fixed

- Stage, independently sign, and verify the Docker Hub manifest digest before moving
  the version and `latest` tags, replacing the deprecated cross-registry `cosign copy`
  path that left the mirror unsigned and failed the release workflow
  ([issue #538](https://github.com/BreachSAFE/qureddy/issues/538),
  [PR #651](https://github.com/BreachSAFE/qureddy/pull/651)).

## [0.9.2] - 2026-09-01

### Added

- Add an authorization-first guided scan example for TLS and SSH targets
  ([PR #548](https://github.com/BreachSAFE/qureddy/pull/548)).

### Fixed

- Populate exact TLS negotiation, legacy-cipher, and certificate-signature identity and
  protocol-neutral classification in native JSON and JSONL evidence and findings, matching
  the core classification used by CBOM output
  ([issue #648](https://github.com/BreachSAFE/qureddy/issues/648),
  [PR #649](https://github.com/BreachSAFE/qureddy/pull/649)).
- Emit exact SSH algorithm identity and core-owned classification on named
  native-JSON evidence, and populate the representative algorithm on the
  classical-alternative finding ([issue #645](https://github.com/BreachSAFE/qureddy/issues/645),
  [PR #647](https://github.com/BreachSAFE/qureddy/pull/647)).
- Populate key-exchange `primitive`, parameter-set, and NIST quantum security
  classifications in native JSON and JSONL findings from the same protocol-neutral
  classifier used by CBOM output ([issue #639](https://github.com/BreachSAFE/qureddy/issues/639),
  [PR #644](https://github.com/BreachSAFE/qureddy/pull/644)).
- Require canonical finding-type and readiness-state pairs before evidence can affect
  endpoint HNDL posture, preventing structurally invalid observations from producing a
  global posture ([issue #598](https://github.com/BreachSAFE/qureddy/issues/598),
  [PR #614](https://github.com/BreachSAFE/qureddy/pull/614)).
- Normalize explicit, inferred, and mixed-case IKE protocol values before HNDL
  classification so equivalent observations cannot produce conflicting posture states
  ([PR #622](https://github.com/BreachSAFE/qureddy/pull/622)).

## [0.9.1] - 2026-08-31

### Changed

- Promote the signed multi-architecture container manifest to Docker Hub without rebuilding;
  verify the Docker Hub digest and copy its signature, attestations, and SBOM references.
- Keep GHCR as the canonical image registry and Docker Hub as a distribution mirror.

## [0.9.0.10] - 2026-08-30

### Fixed

- Anchor post-quantum algorithm matching in `core/pqc.py` so a name that merely contains
  `mlkem`, `ml-kem`, `sntrup`, or `kyber` is no longer classified as post-quantum. An SSH
  server chooses its own KEXINIT algorithm names, so a fabricated name such as
  `xkyber999x25519-sha256` inverted the verdict from `at_risk` to `protected` on an endpoint
  with no post-quantum capability. A token must now start a name component, and a KEM token
  must be followed by its parameter set. Affects `is_pq_kem`, `pq_kem_category`, and
  `has_classical_half`, and therefore both the TLS and SSH verdict paths (#532).

## [0.9.0.9] - 2026-08-26

### Fixed

- Use `breachsafe.io` consistently as the public branding domain.

## [0.9.0.8] - 2026-08-26

### Changed

- Dependabot now monitors digest-pinned Docker base images weekly (#504).

## [0.9.0.7] - 2026-08-26

### Fixed

- Stage the multi-architecture container manifest, sign and verify its digest,
  then promote only the verified digest to the version and `latest` tags (#512).

## [0.9.0.6] - 2026-08-26

### Fixed

- Use Buildx's direct digest template when signing the published multi-arch image.

## [0.9.0.5] - 2026-08-26

### Fixed

- Corrected GHCR manifest digest extraction so the container signing step consumes the published digest format returned by Buildx.

## [0.9.0.4] - 2026-08-26

### Fixed

- Published GHCR image digests are now signed and verified with keyless Cosign in the manifest job.

## [0.9.0.3] - 2026-08-25

### Fixed

- The release-signing verification job now installs the pinned Cosign version used
  by the build job and fails closed when cryptographic verification cannot run.
  This closes #502.
- Corrected two Python 3.14 exception handlers so the duplicate-code CI parser
  accepts the source on every runner.

## [0.9.0.2] - 2026-08-25

### Changed

- Removed personal-owner links and wording from public documentation and
  integration guidance. The pinned golden CI workflow remains unchanged until
  its repository is transferred to the BreachSAFE organization.

## [0.9.0.1] - 2026-08-24

### Fixed

- Corrected the dependency-to-import mapping for `cyclonedx-python-lib` so the
  enforced `deptry` gate recognizes the package's `cyclonedx` Python module.

## [0.9.0.0] - 2026-08-24

### Changed

- Consolidated the public release metadata and integration documentation for
  the EnXemble consumer, OpenSSL runtime, and CycloneDX CBOM output contract.
