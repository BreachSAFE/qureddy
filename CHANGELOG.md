# Changelog

[![Status: Alpha](https://img.shields.io/badge/status-alpha-blue?style=flat-square)](https://github.com/breachsafe/qureddy)
[![Version](https://img.shields.io/badge/version-0.2.57-blue?style=flat-square)](CHANGELOG.md)
[![Keep a Changelog](https://img.shields.io/badge/keep%20a%20changelog-1.1.0-orange?style=flat-square)](https://keepachangelog.com/en/1.1.0/)
[![SemVer](https://img.shields.io/badge/SemVer-2.0.0-blue?style=flat-square)](https://semver.org/spec/v2.0.0.html)

All notable user-visible changes to QuReddy are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and version
numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Distribution policy is explicitly TestPyPI-only for now**: release automation,
  packaging checks, and installation guidance no longer imply that the public PyPI
  package exists or should be probed before an explicit authorization.

## [0.2.57] - 2026-08-24

### Changed

- Made the Rich verdict HNDL-first: future Harvest-Now, Decrypt-Later risk is
  shown before PQC capability, current hardening, and the overall assessment.
- Added a regression test for the canonical CISO summary path and clarified
  console renderer documentation.

## [0.2.56] - 2026-08-24

### Added

- Added independent `hndl_exposure` and `hygiene_status` posture axes so
  post-quantum downgrade exposure and present-day protocol hygiene are visible
  without changing the legacy `effective` readiness field (`#453`).
- Mirrored both axes in Rich, JSON, and CycloneDX CBOM output.

## [0.2.55] - 2026-08-24

### Fixed

- Standardized unexpected CLI error diagnostics through the structured logger
  while preserving the detailed operator message and exit code 70 (`#447`).
- Added opt-in traceback output for `-vvv`; machine-readable stdout remains
  uncontaminated.

## [0.2.54] - 2026-08-24

### Changed

- Documented the temporary Ruff `py313` formatter target compatibility hold while
  the runtime and package floor remain Python 3.14 (`#452`).

## [0.2.53] - 2026-08-23

### Fixed

- SSH scans now support `--output-dir`, producing the same correlated JSON and
  CycloneDX CBOM bundle as TLS scans (`#451`).
- SSH rich output now uses SSH-specific fallback wording instead of a malformed
  TLS legacy-protocol recommendation (`#450`).

## [0.2.52] - 2026-08-23

### Fixed

- SSH posture interpretation now reflects classical host-key authentication, weak
  algorithms, transport hygiene, and Terrapin evidence instead of rendering a
  hybrid-positive headline over a classically weak verdict (`#434`, PR #445).

## [0.2.51] - 2026-08-23

### Fixed

- Corrected posture interpretation so rejected classical control probes are not
  reported as negotiated classical key exchange, and current classical KEX is
  not mislabeled as deprecated protocol exposure (`#432`, `#433`).
- Made the Atheris fuzz gate fail closed on harness failures (`#423`).
- Added release metadata and artifact-version consistency checks before publishing
  (`#424`).

## [0.2.50] - 2026-08-23

### Added

- **Correlated scan bundles** (`#430`, `#435`): one TLS scan can now emit JSON and
  CycloneDX CBOM documents with the same scan identity, timestamps, target, and
  evidence without a second network execution.

## [0.2.49] - 2026-08-23

### Added

- **Structured posture and provenance output** (`#425`): Rich, JSON, and CycloneDX
  CBOM output now share the same interpretation, posture axes, reason codes, policy
  metadata, and source provenance so operators can explain the result consistently.

## [0.2.48] - 2026-08-23

### Fixed

- **MAX quality gates remain executable in GitHub Actions** (`#360`, `#414`):
  the local fail-closed gate is restored while the private common workflow is
  unavailable across the `breachsafe`/`paul007ex` organization boundary.
- **Release identity is consistent**: package metadata, Docker banners, golden
  fixtures, and lock data all report `0.2.48`.

## [0.2.46] - 2026-08-23

### Changed

- **MAX quality gates were prepared for the shared BreachSAFE workflow** (`#360`, `#412`):
  the commit-pinned common `v1.1.1` contract and fail-closed anti-pattern diff gate
  were validated locally; GitHub cross-owner access is tracked by #360.

## [0.2.45] - 2026-08-22

### Fixed

- **Resolver version parsing now uses `packaging.version.Version`** (`#393`): discovery no
  longer maintains a second hand-rolled version parser and invalid path names fall back
  safely.
- **Unused SSH classification paths were removed** (`#394`): dead KEX notes and the
  unwired host-key reason helper no longer create duplicate or stale mechanisms.

## [0.2.44] - 2026-08-22

### Fixed

- **CBOM and output failures now use typed error boundaries** (`#401`): semantic and
  serialization defects map consistently to the internal-error contract instead of
  leaking heterogeneous stdlib exceptions.
- **OpenSSL resolver coverage and platform guidance were expanded** (`#399`): capability
  override/error paths and cross-platform discovery are exercised by the test suite.

### Changed

- **SSH scanner observation builders were separated from orchestration** (`#400`): the
  scanner stays below the size ceiling while preserving output and readiness behavior.

## [0.2.43] - 2026-08-23

### Fixed

- **SSH server identity is now captured as typed evidence** (`#290`): banner software and
  version facts are validated, emitted without changing readiness, and included in CBOM
  endpoint properties.
- **OpenSSL linked-library versions now honor the pinned 3.5.7 floor** (`#389`): executable
  and linked-library validation use one symmetric policy and preserve typed failures.
- **CBOM certificate conformance fixtures now track emitter shape** (`#390`): certificate
  self-signed state is represented and fixture drift fails the conformance gate.

### Changed

- **Deterministic output is named explicitly** (`#323`): `--deterministic` is canonical;
  `--reproducible` remains a hidden compatibility alias.

## [0.2.42] - 2026-08-22

### Security

- **Runtime container images no longer ship build-only pip tooling** (`#382`):
  the final image removes pip and setuptools after installing QuReddy, eliminating
  pip's vendored `msgpack` tree and reducing the runtime attack surface. Build tooling
  remains isolated to the wheel-build stage.

## [0.2.39] - 2026-08-22

### Security

- **OpenSSL launch failure can no longer masquerade as a certificate claim** (`#374`):
  `_is_self_signed` previously caught `OSError`/timeout and returned `False`, laundering a
  local-verifier failure into "certificate is not self-signed". A launch failure now raises
  the typed local-dependency error (exit 3). Certificate and legacy probes likewise no longer
  leak an uncaught `OSError` (Windows WinError 193 / permission-denied) as exit 70.

### Changed

- **All OpenSSL subprocess execution is centralized in one executor** (`#296`):
  new `openssl_probe/executor.py` owns list-form invocation, `shell=False`, stdin selection,
  stream capture, timeout, and partial-output handling, returning a typed `OpenSSLOutcome`
  (with `MISSING`/`UNLAUNCHABLE` classification). The five call sites keep their distinct
  domain policies but share one mechanism, resolving the drifted error handling. Enforced by
  a new AST boundary check (`scripts/check_openssl_boundary.py`) in the release gate; Rule 7.1
  documentation corrected to match reality.

## [0.2.38] - 2026-08-22

### Fixed (input & scan correctness — 0.2.29 milestone)

- **`parse_target` no longer silently drops TLS URL components** (`#366`): userinfo,
  path, query, and fragment are rejected with `TargetParseError` instead of being
  normalized away (which also kept supplied credentials in `original_input`). Mirrors
  the SSH parser; a bare trailing `/` stays accepted.
- **SSH packet parser rejects RFC-invalid framing** (`#367`): `_read_packet_payload`
  now enforces RFC 4253 §6 — padding 4..255 bytes, block alignment, non-negative
  payload — instead of accepting `pad_len=0`/misaligned packets from an untrusted server.
- **Retry allowlist honored across categories** (`#368`): `run_with_retries` continues
  while each failure category is in `retry_on`, rather than stopping the moment a later
  attempt's category differs from the first.
- **`ScanTarget` model boundary hardened** (`#369`): host uses `fullmatch` (rejects a
  trailing newline), SNI must be a valid hostname or `None` (rejects `-oProxyCommand=…`,
  control chars, leading dash flowing into OpenSSL `-servername`), and `scheme` is
  constrained to `{tls, ssh}`.

### Internal

- `HOSTNAME_PATTERN` de-duplicated into `core/models.py` (single source; `core/targets.py`
  imports it), advancing the `#315` dedup effort.

## [0.2.37] - 2026-08-22

### Removed

- **Python 3.12 and 3.13 support. QuReddy now requires Python 3.14** (`#327`).
  Installing on an older interpreter is no longer supported. This is a
  deliberate, no-backward-compat migration.

### Changed

- Everything moved to Python 3.14: `requires-python >=3.14`, classifiers, all CI
  workflows, `release_gate.py`, and the Docker base image (`python:3.14-slim`,
  digest-pinned). The dependency set re-resolved cleanly on 3.14 (all cp314 wheels).
- Fuzzing now runs on Python 3.14 via atheris 3.1 (first cp314 wheel) directly,
  replacing the OSS-Fuzz 3.11 base image (`#325`); ubuntu/amd64 only.
- ruff formatter target held at py313 so it does not emit PEP 758 unparenthesized
  `except` (unparseable by pylint/astroid and pre-3.14 tools) while runtime is 3.14.

### Fixed

- `parse_ssh_target`/`parse_target` now wrap pydantic `ValidationError` as the
  declared `TargetParseError` (found by the atheris-3.14 fuzz gate).

## [0.2.36] - 2026-08-22

### Changed

- All 9 rank-B modules refactored to xenon rank A via helper extraction (`#364`):
  `core/retry`, `output/cbom`, `output/cbom_semantics`, `output/cbom_cipher`,
  `output/console/_errors`, `output/console/_commands`, `cli/_help`, `cli/_execute`,
  `scanners/tls/_legacy_findings`. Behavior and all output are byte-identical
  (golden + conformance unchanged). The MAX quality gate's xenon step is tightened
  to `--max-modules A`, matching breachsafe-common's reusable gate exactly (`#360`).

## [0.2.35] - 2026-08-22

### Changed

- Cyclomatic complexity reduced across `cbom_semantics`, `core/targets`, `cbom_metadata`,
  and console helpers; all blocks now rank <= B (`#341`). MAX-tier lint cleanups (refurb
  idioms, jscpd 0 clones) with byte-identical scan output (`#342`).

### Fixed

- CLI stderr-merge detection fails **closed** in machine mode when fd introspection is
  genuinely undetermined, while still failing open when no real fd exists (CliRunner/pytest
  contract preserved) (`#344`).
- Uniform DN-anchoring across the certificate public-key and signature probes, closing a
  DN-injection path where a crafted subject/issuer value could win the first regex match
  (`#344`).
- `bump_version.py` now stamps the six version-bearing doc literals (README badge, Dockerfile
  `QUREDDY_VERSION`, BADGE.md, cli.md, json-schema.md) that had drifted behind releases
  (`#340`).

### Documentation

- Honest install path (TestPyPI, not a 404 PyPI page), Docker-first quickstart, full CBOM
  property-key reference (all 14 `qureddy:` keys incl. `#309` rollup), milestones true-up,
  and removal of public-doc deferrals to the gitignored `.agents/skills/`
  (`#335`, `#348`, `#336`, `#339`, `#338`, `#297`, `#294`).

### Internal

- Three oversized test files split under the 400-line ceiling; shared CBOM builders extracted
  to `tests/_cbom_fixtures.py` (`#298`).

## [0.2.34] - 2026-08-22

### Fixed

- Live/test references to the pre-#330 rule id `tls.hybrid.negotiated_x25519mlkem768` are
  updated to the structural `tls.hybrid.negotiated_pq`. The #330 rename had missed the live
  test suite (excluded from the release gate), the hardcoded test fixtures, the golden files,
  and the p1 conformance fixture — so the live PQ-hybrid assertion checked a rule id the policy
  no longer emits. No product behavior change.

## [0.2.33] - 2026-08-22

### Fixed

- A defect at the CBOM render boundary (e.g. a semantic-validator `ValueError`) now maps to the
  exit-code contract — `EXIT_INTERNAL_ERROR` (70) with an operator diagnostic — instead of
  escaping as an internal traceback. Applies to both `scan tls` and `scan ssh`. (#344)

## [0.2.32] - 2026-08-22

### Fixed

- CBOM: a fully post-quantum certificate whose issuer signature and subject key use the same
  parameter set (ML-DSA-87 signature + ML-DSA-87 key) no longer emits two components with the
  same bom-ref — which cyclonedx silently renamed to a random ref, orphaning a component and
  breaking `--reproducible`. Both references now point to one shared algorithm asset, and the
  semantic validator rejects any surviving auto-generated bom-ref. (#343)

## [0.2.31] - 2026-08-22

### Added

- TLS PQ readiness now probes all three standardized ML-KEM hybrid groups (X25519MLKEM768,
  SecP256r1MLKEM768, SecP384r1MLKEM1024), so a server that supports only a non-default hybrid
  is still detected as `transitional_hybrid` (#337). Supplementary group probes record support
  without emitting spurious findings on rejection. Completes the coverage half of #330.

## [0.2.30] - 2026-08-22

### Fixed

- PQC-readiness classification is now structural, fixing a false negative in the headline
  verdict (#330): a server negotiating any standardized post-quantum hybrid TLS group
  (SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519Kyber768, ...) is now reported
  `transitional_hybrid` instead of `quantum_vulnerable`. Previously only the literal
  `X25519MLKEM768` matched. A pure post-quantum group is reported `quantum_safe`, and the
  readiness rollup no longer lets the by-design classical control probe downgrade a genuinely
  safe/hybrid verdict. TLS and SSH now share one structural PQ classifier.

## [0.2.29] - 2026-08-22

### Changed

- CBOM evidence occurrences are now complete and richer (#326): every scan evidence item maps
  to an occurrence (a bare failure/certificate record with no crypto subject now attaches to
  the endpoint instead of being dropped), and each occurrence's `additionalContext` grammar
  gains `confidence` and (when co-observed) `cipher_suite`. A consumer keying on the CBOM alone
  recovers the full evidence trail without the native JSON. Parse contract:
  docs/reference/cbom-occurrence-provenance.md.

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

1. [0.2.57](#0257---2026-08-24)
2. [0.2.56](#0256---2026-08-24)
3. [0.2.55](#0255---2026-08-24)
4. [0.2.53](#0253---2026-08-23)
5. [0.2.52](#0252---2026-08-23)
6. [0.2.51](#0251---2026-08-23)
7. [0.2.50](#0250---2026-08-23)
8. [0.2.49](#0249---2026-08-23)
9. [0.2.48](#0248---2026-08-23)
10. [0.2.46](#0246---2026-08-23)
11. [0.2.45](#0245---2026-08-22)
12. [0.2.44](#0244---2026-08-22)
13. [0.2.43](#0243---2026-08-23)
14. [0.2.42](#0242---2026-08-22)
15. [0.2.39](#0239---2026-08-22)
16. [0.2.38](#0238---2026-08-22)
17. [0.2.37](#0237---2026-08-22)
18. [0.2.36](#0236---2026-08-22)
19. [0.2.35](#0235---2026-08-22)
20. [0.2.34](#0234---2026-08-22)
21. [0.2.33](#0233---2026-08-22)
22. [0.2.32](#0232---2026-08-22)
23. [0.2.31](#0231---2026-08-22)
24. [0.2.30](#0230---2026-08-22)
25. [0.2.29](#0229---2026-08-22)
26. [0.2.28](#0228---2026-08-22)
27. [0.2.27](#0227---2026-08-22)
28. [0.2.26](#0226---2026-08-22)
29. [0.2.25](#0225---2026-08-22)
30. [0.2.24](#0224---2026-08-22)
31. [0.2.23](#0223---2026-08-22)
32. [0.2.22](#0222---2026-08-22)
33. [0.2.21](#0221---2026-08-22)
34. [0.2.20](#0220---2026-08-22)
35. [0.2.18](#0218---2026-08-22)
36. [0.2.17](#0217---2026-08-21)
37. [0.2.16](#0216---2026-08-21)
38. [0.2.15](#0215---2026-08-21)
39. [0.2.14](#0214---2026-08-19)
40. [0.2.13](#0213---2026-08-04)
41. [0.2.12](#0212---2026-07-28)
42. [0.2.11](#0211---2026-07-28)
43. [0.2.10](#0210---2026-07-28)
44. [0.2.9](#029---2026-07-28)
45. [0.2.8](#028---2026-07-28)
46. [0.2.7](#027---2026-07-28)
47. [0.2.6](#026---2026-07-28)
48. [0.2.5](#025---2026-07-28)
49. [0.2.4](#024---2026-07-28)
50. [0.2.3](#023---2026-07-27)
51. [0.2.2](#022---2026-07-27)
52. [0.2.1](#021---2026-07-27)
53. [0.2.0](#020---2026-07-27)
54. [0.1.0](#010---2026-05-10)

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
