# Changelog

[![Status: Alpha](https://img.shields.io/badge/status-alpha-blue?style=flat-square)](https://github.com/breachsafe/qureddy)
[![Version](https://img.shields.io/badge/version-0.2.28-blue?style=flat-square)](CHANGELOG.md)
[![Keep a Changelog](https://img.shields.io/badge/keep%20a%20changelog-1.1.0-orange?style=flat-square)](https://keepachangelog.com/en/1.1.0/)
[![SemVer](https://img.shields.io/badge/SemVer-2.0.0-blue?style=flat-square)](https://semver.org/spec/v2.0.0.html)

All notable user-visible changes to QuReddy are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and version
numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.28] - 2026-08-22

### Added

- The CBOM metadata now carries the full scan summary rollup: `qureddy:scan.finding_count` and
  `qureddy:scan.highest_severity` (and `qureddy:scan.failure_category` when set), alongside the
  existing `qureddy:scan.readiness`/`status`. A consumer keying on the CBOM alone no longer needs
  the native JSON to see the headline counts. (#309)

## [0.2.27] - 2026-08-22

### Changed

- Internal de-duplication of the CBOM and SSH layers (no behavior change; CBOM output is
  byte-identical). Symmetric-cipher classification (strength + primitive) is now one shared
  `cbom_cipher` helper instead of four drifting copies across the TLS, legacy-TLS, and SSH
  emitters; bom-ref grammar is one shared `algorithm_ref`/`protocol_ref`; the SSH scanner's
  offered-evidence and weak-finding builders are each one helper instead of five and three
  copies. (#315)

## [0.2.26] - 2026-08-22

### Added

- The CBOM now records a certificate's own subject public key as a linked CycloneDX
  cryptographic-asset: its algorithm and key size (e.g. `RSA-2048`, `EC-256`), the classical
  security strength (NIST SP 800-57), and a readiness verdict, referenced from the certificate
  via native `certificateProperties.subjectPublicKeyRef`. The leaf key is the quantum-relevant
  fact a harvest-now-decrypt-later adversary attacks, and it was previously absent from the
  CBOM. Classification lives in a shared, protocol-agnostic helper that SSH host keys (#291)
  and CA/chain keys reuse, so the depth is emitted once rather than per protocol. Uses native
  library fields only (no new post-serialization patching); validated by two independent
  CycloneDX 1.7 validators and mints a NIST-oscal-cli-valid OSCAL POA&M through
  breachsafe-mint-oscal. (#313)

## [0.2.25] - 2026-08-22

### Changed

- CBOM evidence occurrences now record probe provenance as a strict `key=value` grammar in
  `additionalContext` (`observation=negotiated; evidence_type=tls.negotiation; role=...;
  expected=...; return_code=0; command_sha256=...`) instead of a prose sentence. A consumer
  reads each field by splitting on `"; "` then partitioning on the first `"="`, with no
  scraping of free text. The command digest keeps its reproducibility guarantee (attributed
  by basename, byte-stable in `--reproducible`). Parse contract:
  docs/reference/cbom-occurrence-provenance.md. (#307)

## [0.2.24] - 2026-08-22

### Added

- CBOM now inventories accepted legacy TLS ciphers as first-class CycloneDX
  cryptographic-asset components (previously only free text in an evidence notes blob).
  Each carries its primitive and classical strength, an evidence occurrence, and a verdict
  property — `classically_weak` for a known-weak cipher, otherwise `quantum_vulnerable` —
  so the weak/legacy-cipher surface is directly queryable by GRC/SBOM tooling. Validated by
  two independent CycloneDX 1.7 validators and mints a NIST-oscal-cli-valid OSCAL POA&M
  through breachsafe-mint-oscal. (#303)

## [0.2.23] - 2026-08-22

### Changed

- CBOM findings and evidence now use native CycloneDX 1.7 structures instead of a flat
  `qureddy:` property namespace: evidence is attached to the crypto asset it describes as
  `component.evidence.occurrences`, findings are top-level `annotations` linked to their
  subject asset (carrying the full description and citations), and each finding's verdict
  (readiness, severity, rule) is a queryable property on that asset. `metadata.properties`
  now carries scan, target, and tool provenance only. Validated by two independent
  CycloneDX 1.7 validators and mints a NIST-oscal-cli-valid OSCAL POA&M through
  breachsafe-mint-oscal. A consumer that keyed on the old flat `qureddy:finding.NN.*` /
  `qureddy:evidence.NN.*` property names must migrate to the annotations, occurrences, and
  verdict properties. (#287, #285)

## [0.2.22] - 2026-08-22

### Changed

- The TLS and SSH scanners now emit CycloneDX crypto-asset components through one
  shared emitter, so both protocols produce assets with identical structure. (#288)

### Fixed

- SSH symmetric ciphers (AES, ChaCha20) now carry `classicalSecurityLevel` instead of a
  misleading `nistQuantumSecurityLevel: 0`, matching how the TLS cipher suites are
  represented; SSH MACs carry neither level. (#286)
- The per-evidence CBOM property is named `observed_algorithm` rather than
  `negotiated_group`, since SSH records offered host keys, ciphers, and MACs there,
  which are neither groups nor negotiated. (#286)
- The CBOM no longer emits an empty-string `stdout_sha256` for probes that produced no
  standard output. (#286)

## [0.2.21] - 2026-08-22

### Fixed

- The Docker image builds its wheel from source in an in-image stage, so a fresh
  clone `docker build .` succeeds with no separate wheel-build step. The build
  previously failed after the OpenSSL compile because it copied a host-built
  wheel that a fresh checkout does not have. (#253)

## [0.2.20] - 2026-08-22

### Changed

- Shared scanner core: the TLS and SSH scanners now share one readiness and
  severity rollup, one record-ID minter, and one endpoint-asset builder, in place
  of the per-scanner copies each carried before. (#248)

### Fixed

- SSH readiness rollup covered four of the six readiness tiers, so a pure
  post-quantum SSH key exchange rolled up to `unknown` instead of `quantum_safe`.
  The shared rollup covers all six tiers. (#248)
- An SSH scan that produced zero findings raised an error during severity rollup.
  The shared rollup reports no severity for an empty finding set. (#248)

## [0.2.18] - 2026-08-22

### Added

- SSH CBOM parity with TLS: an SSH scan now inventories every key-exchange group,
  host key, cipher, and MAC as CycloneDX crypto assets, each with the correct
  primitive and post-quantum security level. (#241, #242, #243)
- Fuzzing: Atheris harnesses for the TLS and SSH parsers, with an advisory
  ClusterFuzzLite job on pull requests. (#86, #239)

### Fixed

- SSH PQ-hybrid key exchange over non-x25519 curves (ML-KEM with P-256/P-384, and the
  Kyber hybrids) is now classified post-quantum; such endpoints previously read as
  `quantum_vulnerable`. (#247)
- A peer-closed SSH connection now reports `target_connect_failed` rather than a parse
  ambiguity. (#244)

### Security

- The release workflow fails if signing did not run and produce the `.sigstore` bundles,
  so an unsigned release cannot ship silently. (#232)

### Changed

- `bump_version` single-sources the version across pyproject, the CHANGELOG, the
  Dockerfile ARG, and the lockfile. (#206)

## [0.2.17] - 2026-08-21

### Added

- Output ergonomics for `scan tls` and `scan ssh`: `--output PATH` (`-o`) writes the
  machine document to a file while stdout stays clean, `--compact` minifies JSON and
  CBOM, and `--min-severity` filters the findings table. (#133)
- SSH host keys now appear in the CBOM as cryptographic-asset components, and weak SSH
  key-exchange algorithms such as diffie-hellman-group1-sha1 are flagged. (#143)

### Fixed

- SLH-DSA (FIPS 205) certificate signatures are now classified as post-quantum. (#201)
- Evidence integrity: `stdout_sha256` now attests exactly the stream that `stdout_excerpt`
  is a prefix of. (#202)
- `--reproducible` CBOM output is now byte-identical across hosts. Host-specific
  executable paths are canonicalized before hashing. (#207, #196)

### Security

- The Docker wheel install is recognized as pinned by OpenSSF Scorecard
  (Pinned-Dependencies 10/10), with an optional `QUREDDY_WHEEL_SHA256` integrity gate. (#221)
- OpenSSF Scorecard and CI hardening: least-privilege workflow permissions, CodeQL on
  push, and a canonical-source provenance gate. (#224, #229)

## [0.2.16] - 2026-08-21

### Changed

- Relicensed back to the **Apache License 2.0** (OSI-approved open source). QuReddy is
  the open-source scanner; the PolyForm Noncommercial license now applies only to the
  separate QuReddy Pro edition. Releases 0.2.13-0.2.15 were published under PolyForm
  Noncommercial and those copies retain those terms; 0.2.16 onward is Apache-2.0. This
  restores OpenSSF Best Practices badge eligibility (PolyForm is not OSI-approved).

## [0.2.15] - 2026-08-21

### Fixed

- TLS capability detection now requires exact OpenSSL 3.5.7 for both the
  executable and any explicitly reported linked library. Releases below the
  pin remain `local_openssl_too_old`; other parseable releases use
  `local_openssl_version_mismatch` and exit `3`.

## [0.2.14] - 2026-08-19

### Added

- `--log PATH` on `scan tls`: capture a run's structured logs to a file (INFO and above;
  honors `--json-logs`). stdout stays the `--format` data channel. When capturing to a file,
  the machine-format auto-quiet does not apply and the level is floored at INFO so a clean run
  still records its story. A path that cannot be written is a usage error (exit 4), reported
  before any scan work, and the file is closed even when the run exits early. `scan ssh` shares
  the same log-capture helper (`start_run_logging`) so the wiring lives in one place.

## [0.2.13] - 2026-08-04

### Changed

- Future releases are source-available under PolyForm Noncommercial License 1.0.0.
  Releases through v0.2.12 remain available under their published Apache-2.0 terms.
- Release-facing documentation, package metadata, and Docker OCI metadata now identify
  the PolyForm license consistently.

### Fixed

- Docker's default build argument and container-publication workflow now use the current
  release version instead of stale 0.2.x defaults.

## Contents

1. [0.2.28](#0228---2026-08-22)
2. [0.2.27](#0227---2026-08-22)
3. [0.2.26](#0226---2026-08-22)
4. [0.2.25](#0225---2026-08-22)
5. [0.2.24](#0224---2026-08-22)
6. [0.2.23](#0223---2026-08-22)
7. [0.2.22](#0222---2026-08-22)
8. [0.2.21](#0221---2026-08-22)
9. [0.2.20](#0220---2026-08-22)
10. [0.2.18](#0218---2026-08-22)
11. [0.2.17](#0217---2026-08-21)
12. [0.2.16](#0216---2026-08-21)
13. [0.2.15](#0215---2026-08-21)
14. [0.2.14](#0214---2026-08-19)
15. [0.2.13](#0213---2026-08-04)
16. [0.2.12](#0212---2026-07-28)
17. [0.2.11](#0211---2026-07-28)
18. [0.2.10](#0210---2026-07-28)
19. [0.2.9](#029---2026-07-28)
20. [0.2.8](#028---2026-07-28)
21. [0.2.7](#027---2026-07-28)
22. [0.2.6](#026---2026-07-28)
23. [0.2.5](#025---2026-07-28)
24. [0.2.4](#024---2026-07-28)
25. [0.2.3](#023---2026-07-27)
26. [0.2.2](#022---2026-07-27)
27. [0.2.1](#021---2026-07-27)
28. [0.2.0](#020---2026-07-27)
29. [0.1.0](#010---2026-05-10)

## [0.2.12] - 2026-07-28

### Added

- CBOM classifies certificate and host-key signature algorithms natively
  (`primitive: signature`, sign/verify; classical at nistQuantumSecurityLevel 0,
  ML-DSA at its FIPS 204 category), closing the last empty-`algorithmProperties` gap
  so a foreign crypto-aware CycloneDX tool understands the cert posture. (#177)

### Changed

- Documented the CBOM two-layer design and CycloneDX interoperability model in
  `docs/explanation/cbom-design.md`, cross-linked from the README and CBOM reference.

## [0.2.11] - 2026-07-28

### Added

- Shell tab completion: `qureddy --install-completion` (bash/zsh/fish); `scan <tab>` offers
  tls/ssh and `--format <tab>` offers rich/json/cbom. The completion options are hidden from
  `--help` so the help screens stay clean. (#125)

## [0.2.10] - 2026-07-28

### Added

- Opt-in SSRF guard: `QUREDDY_BLOCK_INTERNAL_TARGETS=1` (or `block_internal=True`)
  rejects loopback/link-local/private/metadata targets before network access, for
  embedders that accept untrusted targets; the CLI default is unchanged. Threat model
  documents the boundary. (#134)
- SSH scanner flags `ssh-rsa` (RSA/SHA-1) weak host keys in addition to `ssh-dss`,
  with a per-algorithm justification note; `rsa-sha2-*` stay unflagged. (#143)
- Release workflow signs the wheel + sdist with cosign keyless (OIDC) and attaches the
  signatures as GitHub Release assets (OpenSSF Signed-Releases). (#121)

### Changed

- Internal: `cbom.py` split into `cbom.py` + `cbom_metadata.py` + `cbom_components.py`
  to stay under the file-size ceiling; CBOM output is byte-identical. (#171)

## [0.2.9] - 2026-07-28

### Added

- CBOM carries per-finding verdicts (`qureddy:finding.{i}.severity/readiness/rule_id/...`),
  completing readiness/severity parity with `--format json`. (#147, PR #170)

### Fixed

- `--reproducible` now also omits the host-specific `qureddy:openssl.path` and the
  retry-varying `qureddy:scan.total_attempts`, so two hosts observing identical crypto
  produce the same digest. Evidence/finding index property names are zero-padded so they
  sort lexicographically in scan order. (#147 audit)

## [0.2.8] - 2026-07-28

### Added

- CBOM carries the full evidence/provenance trail as `qureddy:evidence.{i}.*` metadata
  properties: source, observation, probe_role, and the probe command SHA-256 +
  return_code + stdout/stderr SHA-256, so every crypto assertion is traceable. (#149, PR #168)
- `--reproducible` (TLS and SSH) omits the per-run identity fields (serialNumber,
  timestamp, scan id/timing, evidence duration) so the same scan is byte- and
  digest-identical for content addressing. (#162, PR #167)

## [0.2.7] - 2026-07-28

### Fixed

- Trailing-dot absolute FQDNs (`www.google.com.`) are accepted as targets and the
  trailing dot is stripped from the on-wire SNI (RFC 6066). (#130, PR #164)
- The Phase-7 CI audit gate no longer expects a `windows-latest` artifact the matrix
  never produces, so it can actually pass. (#141, PR #163)
- The CBOM repeatability check normalizes the per-run scan id/timing added in 0.2.6,
  fixing a wall-clock race. (#152 follow-up, PR #165)
- The runtime CBOM semantic validator now also walks `signatureAlgorithmRef` and
  cipher-suite algorithm refs, and the validation-contract docs describe accurately
  what runs at runtime versus in CI. (#144, PR #166)

## [0.2.6] - 2026-07-28

### Added

- CBOM carries scan-identity and structured target metadata (`qureddy:scan.*`,
  `qureddy:target.*` incl. SNI) for JSON parity. (#152, PR #159)
- CBOM openssl tool component carries the capability flags
  (`supports_tls13_groups`, `supports_x25519mlkem768`) and path. (#151, PR #160)
- CBOM emits the negotiated AEAD cipher suite as a standalone crypto asset and marks
  every algorithm with `qureddy:observation` (negotiated/offered/observed). (#150, PR #161)

## [0.2.5] - 2026-07-28

### Fixed

- Malformed target URLs (e.g. an unclosed `[` IPv6 bracket) now exit 4 (usage) instead
  of 70 (internal error). (#139, PR #148)
- A connect-timeout with no TCP `CONNECTED` is classified as unreachable
  (`target_connect_failed`) so the scanner short-circuits instead of sweeping a dead
  host for ~180s. (#138, PR #154)
- CBOM `protocolProperties.version` for TLS is the bare CycloneDX form (`1.3`, not
  `TLSv1.3`), matching the SSH path. (#140, PR #155)
- A completed legacy sweep that confirms a protocol is absent is recorded as
  `not_offered`, not `offered`, so the CBOM no longer claims modern targets provide
  TLS 1.0/1.1. (#137, PR #156)
- The `--sni` override is validated as a hostname, rejecting embedded newlines, control
  characters, ANSI escapes, and leading dashes before they reach OpenSSL. (#145, PR #158)

### Added

- CBOM algorithm components carry structured `algorithmProperties` (primitive,
  parameterSetIdentifier, nistQuantumSecurityLevel, cryptoFunctions) for the observed
  key-exchange groups. (#146, PR #157)

## [0.2.4] - 2026-07-28

### Fixed

- Certificate validity dates are parsed locale-independently, so they are no longer
  silently dropped from the CBOM on a non-English host. (#116, PR #126)
- The CBOM now carries qureddy's headline readiness verdict in `metadata.properties`
  (`qureddy:scan.readiness`); previously it appeared only in `--format json`. (#132, PR #135)
- Non-canonical port forms (Unicode digits, underscores, a leading sign, surrounding
  whitespace) are rejected instead of being silently corrected by `int()`. (#128, PR #136)
- The published container image is stamped with the real release version in its
  `org.opencontainers.image.version` OCI label instead of a fixed `0.2.0`. (#123, PR #127)
- Corrected the `--sni` help and IP-target examples, which wrongly claimed SNI is
  required for IP targets; it is an override for name-based virtual hosts. (#122, PR #129)

## [0.2.3] - 2026-07-27

### Changed

- Standardized the exact OpenSSL 3.5.7 LTS baseline across CI, the setup action,
  fixtures, and contributor documentation.
- Removed em and en dashes from shipped and user-facing documentation per the project
  style rule.

### Fixed

- Golden output contracts and the version badge move with the package version through
  scripts/bump_version.py (single source), so a bump no longer breaks test_golden_output.

## [0.2.2] - 2026-07-27

### Changed

- Documentation Docker examples reference the floating `:latest` tag instead of
  a pinned version, so they do not go stale on each release (pin an explicit
  `:X.Y.Z` in production).
- The container publish workflow also tags `:latest`.

### Added

- `scripts/bump_version.py`; single-source version bump driven by
  `pyproject.toml`, updating the README version badge so a release touches one
  number.

## [0.2.1] - 2026-07-27

### Fixed

- Align the published package metadata with the supported Python range of
  `>=3.12`, including Python 3.13.
- Rebuild release artifacts from the tagged source tree so package metadata,
  documentation, and CI agree.

## [0.2.0] - 2026-07-27

Version 0.2.0 adds SSH scanning, certificate signature observation, legacy TLS
enumeration, and CycloneDX 1.7 CBOM output. It also completes the repository
cutover and proves the wheel and source distribution across supported
platforms.

### Added

- SSH and SFTP endpoint scanning through `qureddy scan ssh TARGET`. The scanner
  reads the server identification and KEXINIT offer through a direct socket,
  classifies hybrid key exchange and weak host keys, and requires no OpenSSL.
  See [PR #22](https://github.com/breachsafe/qureddy/pull/22).
- Leaf certificate signature algorithm observation in the TLS scan, including
  ML-DSA recognition. See
  [issue #7](https://github.com/breachsafe/qureddy/issues/7) and
  [PR #8](https://github.com/breachsafe/qureddy/pull/8).
- TLS 1.0, 1.1, and 1.2 enumeration with observed cipher suites in the default
  TLS scan. See [issue #11](https://github.com/breachsafe/qureddy/issues/11).
- CycloneDX 1.7 CBOM output for TLS and SSH through `--format cbom`. The
  endpoint is the metadata root, local collector software is tool provenance,
  positively observed crypto assets use stable references, and scan status is
  retained in metadata properties. See
  [issue #31](https://github.com/breachsafe/qureddy/issues/31) and
  [PR #48](https://github.com/breachsafe/qureddy/pull/48).
- Final-byte CBOM conformance against pinned CycloneDX 1.7.1 schemas,
  `cyclonedx-cli` 0.33.1, semantic reference and secret checks, positive and
  negative fixtures, installed-console canaries, and deterministic renders.
  See [issue #32](https://github.com/breachsafe/qureddy/issues/32) and
  [PR #51](https://github.com/breachsafe/qureddy/pull/51).
- Root `-V` and `--version`, `-h` help, TLS and SSH help examples, and exit
  code `70` for an unhandled internal error. The installed entry point remains
  `qureddy.cli:main` so usage errors map to exit `4`.

### Changed

- The package name is `breachsafe-qureddy`, the installed command is
  `qureddy`, and the package version is single-sourced in `pyproject.toml`.
- Canonical repository, issue, documentation, and package metadata URLs now
  use `github.com/breachsafe/qureddy`. See
  [PR #21](https://github.com/breachsafe/qureddy/pull/21).
- `src/qureddy/cli.py` is now a focused `src/qureddy/cli/` package without
  changing the installed entry point. Oversized scanner and renderer paths
  were split behind the repository size policy. See
  [issue #30](https://github.com/breachsafe/qureddy/issues/30) and
  [PR #47](https://github.com/breachsafe/qureddy/pull/47).
- The source distribution uses an explicit include allowlist.
- Rich output shows separate readiness and protocol facts and includes the
  observed SSH hybrid group when available. See
  [PR #23](https://github.com/breachsafe/qureddy/pull/23),
  [PR #24](https://github.com/breachsafe/qureddy/pull/24),
  [PR #25](https://github.com/breachsafe/qureddy/pull/25),
  [PR #26](https://github.com/breachsafe/qureddy/pull/26),
  [PR #27](https://github.com/breachsafe/qureddy/pull/27),
  [PR #28](https://github.com/breachsafe/qureddy/pull/28), and
  [PR #29](https://github.com/breachsafe/qureddy/pull/29).
- Build dependencies and release tools are pinned where deterministic artifact
  evidence requires it. The exact wheel and source distribution pass archive
  purity, metadata, runtime-only vulnerability audit, and clean wheel, source,
  and pipx installation on Linux, macOS, and Windows. See
  [issue #33](https://github.com/breachsafe/qureddy/issues/33) and
  [PR #50](https://github.com/breachsafe/qureddy/pull/50).

### Fixed

- Machine JSON and CBOM modes default to quiet logging and keep standard
  output parseable under normal and merged-stream failure paths. Explicit
  verbosity still produces diagnostics on standard error. See
  [issue #15](https://github.com/breachsafe/qureddy/issues/15) and
  [PR #18](https://github.com/breachsafe/qureddy/pull/18).
- LibreSSL has a distinct local capability failure and remediation message.
  See [issue #10](https://github.com/breachsafe/qureddy/issues/10) and
  [PR #17](https://github.com/breachsafe/qureddy/pull/17).
- Certificate self-signed status requires signature verification; name
  equality alone is not accepted.
- OpenSSL capability, TLS probe, legacy protocol, and certificate subprocesses
  preserve bounded timeouts and typed failure categories.
- SSH target parsing rejects foreign schemes, credentials, paths, query
  strings, fragments, ambiguous IPv6, and noncanonical numeric IP forms before
  network access. See [issue #40](https://github.com/breachsafe/qureddy/issues/40).
- Live policy tests assert the target-specific finding that the fixture
  establishes instead of a mutable aggregate posture. See
  [issue #39](https://github.com/breachsafe/qureddy/issues/39).
- Runtime dependency resolution, formatting, strict type checking, dependency
  declarations, and REUSE metadata are green on the release stack. See
  [issue #30](https://github.com/breachsafe/qureddy/issues/30).

## [0.1.0] - 2026-05-10

Initial public release of the TLS 1.3 readiness scanner. The public
[`v0.1.0`](https://github.com/breachsafe/qureddy/releases/tag/v0.1.0) tag
contains:

### Added

- forced `X25519MLKEM768` hybrid and `X25519` classical control probes through
  the supported OpenSSL runtime;
- Rich and `qureddy.scan.v1` JSON output;
- typed target, handshake, SNI, middlebox, parser, and local OpenSSL failures;
- bounded retry configuration for selected transient TLS failures;
- normalized hostname, port, URL, IPv4, IPv6, and SNI target handling;
- exit codes `0`, `2`, `3`, `4`, and `70`;
- structured diagnostics on standard error;
- Apache 2.0 licensing and repository quality gates.

The `v0.1.0` tag and the promoted `main` branch have unrelated Git history.
This changelog therefore links the tag directly instead of publishing a
misleading commit comparison.
