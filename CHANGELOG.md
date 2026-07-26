# Changelog

[![Status: Alpha](https://img.shields.io/badge/status-alpha-blue?style=flat-square)](docs/reference/milestones.md)
[![Version](https://img.shields.io/badge/version-0.1.0-blue?style=flat-square)](CHANGELOG.md)
[![Keep a Changelog](https://img.shields.io/badge/keep%20a%20changelog-1.1.0-orange?style=flat-square)](https://keepachangelog.com/en/1.1.0/)
[![SemVer](https://img.shields.io/badge/SemVer-2.0.0-blue?style=flat-square)](https://semver.org/spec/v2.0.0.html)

All notable changes to QuReddy are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). QuReddy uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

OpenSSF Best Practices Badge target: passing tier by MVP 0.6, silver by v1.0.

## [Unreleased]

### Added

- `--version` / `-V` flag at the root and on every subcommand, printing the locked `BreachSAFE QuReddy <version> -- https://www.breachsafe.ai` banner. PR [#55](https://github.com/breachsafe/qureddy/pull/55).
- `qureddy scan tls --help` now includes `EXAMPLES`, `EXIT CODES`, and `ENVIRONMENT` sections in the epilog, rendered with literal newline preservation (Click `\b` form-feed convention). Closes [#71](https://github.com/breachsafe/qureddy/issues/71). PR [#73](https://github.com/breachsafe/qureddy/pull/73).
- Exit code **70** (`EXIT_INTERNAL_ERROR`, BSD `sysexits.h` `EX_SOFTWARE`) for internal qureddy bugs. CI scripts branching on `$? == 2` can now trust that 2 means "target scan failed", not "qureddy crashed". Closes [#12](https://github.com/breachsafe/qureddy/issues/12). Implementation in PR [#51](https://github.com/breachsafe/qureddy/pull/51).
- Failure category classification for unreadable OpenSSL version output — capability checks against ancient or non-standard OpenSSL builds now produce a typed `local_dependency_unusable` outcome rather than crashing. Closes [#16](https://github.com/breachsafe/qureddy/issues/16). PR [#83](https://github.com/breachsafe/qureddy/pull/83).
- Failure category classification for broken OpenSSL capability checks (segfaults, wrong-binary-name, missing PQ groups) — these now route through the typed exception hierarchy instead of bubbling raw subprocess errors. Closes [#10](https://github.com/breachsafe/qureddy/issues/10). PR [#81](https://github.com/breachsafe/qureddy/pull/81).
- Diátaxis documentation structure: `docs/{tutorials,how-to,reference,explanation,contributors}/`. Standard recorded in [ADR 0002](docs/contributors/adr/0002-diataxis-documentation-standard.md).
- Tutorial: `docs/tutorials/your-first-scan.md`.
- How-to guides: `docs/how-to/scan-ip-with-sni.md`, `docs/how-to/json-output-for-ci.md`.
- Reference docs: `docs/reference/cli.md`, `docs/reference/exit-codes.md`, `docs/reference/failure-categories.md`, `docs/reference/json-schema.md`, `docs/reference/milestones.md`.
- Explanation docs: `docs/explanation/why-hybrid-pq.md`, `docs/explanation/hndl.md`, `docs/explanation/threat-model.md`.
- ADR 0001 — `--trace` flag and verbosity refactor (Accepted; implementation pending).
- ADR 0003 — CLI `--help` rewrite per best-practice patterns (Implementing; slices 1–3 of #41 shipped, slice 4 in progress).
- ADR 0004 — multi-scanner architecture for MVP 0.2 (Proposed).
- ADR 0005 — splitting oversized files (Proposed; tracks the cli.py + openssl_probe.py refactor).

### Fixed

- `--format json`/`--format cbom` stdout now stays exactly one parseable document under genuine shell `2>&1`: the failure-path operator hint is suppressed when stderr is fd-merged into a non-terminal stdout, and only there — separate streams and rich mode keep the actionable stderr message from issue #274. Part of [#30](https://github.com/breachsafe/qureddy/issues/30).
- `scan ssh` probe failures in `--format json`/`cbom` now emit a failure-state ScanResult document on stdout (exit 2 unchanged) instead of leaving stdout completely empty, matching the `scan tls` failure contract. Part of [#30](https://github.com/breachsafe/qureddy/issues/30).
- `--version` / `-V` on a subcommand (e.g. `qureddy scan tls --version`) now prints a clear error pointing the user at the root-level form, instead of Click's default cryptic "no such option" message. Closes [#64](https://github.com/breachsafe/qureddy/issues/64). PR [#65](https://github.com/breachsafe/qureddy/pull/65).
- `--v`, `--vv`, `--vvv`, `--verbos` typos at the root level now produce a helpful hint pointing the user at the single-dash POSIX-stacking form (`-v`, `-vv`, `-vvv`), instead of Click's default "no such option" message. Closes [#74](https://github.com/breachsafe/qureddy/issues/74). PR [#80](https://github.com/breachsafe/qureddy/pull/80).
- TLS scanner parser now strictly validates input contract (no trailing whitespace surprises, no NUL-byte injection paths, no silent fallback on unparseable group lines). Closes [#8](https://github.com/breachsafe/qureddy/issues/8) and [#9](https://github.com/breachsafe/qureddy/issues/9). PR [#87](https://github.com/breachsafe/qureddy/pull/87).

### Changed

- `src/qureddy/cli.py` (936 lines) split into the `src/qureddy/cli/` package per [ADR 0005](docs/contributors/adr/0005-splitting-oversized-files.md) (now Accepted): `_errors`, `_execute`, `_help`, `_options`, `_render`, `main`, `scan`, `ssh`. No behavior change — `qureddy.cli:main` entry point, `from qureddy.cli import app`, all help output, and every exit code are identical; ADR 0005's `_fail(message, code)` helper consolidation included. Part of [#30](https://github.com/breachsafe/qureddy/issues/30).
- Engineering and agent docs moved from `docs/` root into `docs/contributors/` per Diátaxis. `git mv` preserves blame. See ADR 0002 for the full move table.
- All internal markdown links updated to the new paths.

## [0.1.0] - 2026-04-26

Initial shipping release of QuReddy. The TLS scanner — MVP 0.1.

### Added

- TLS scanner. `qureddy scan tls TARGET` runs hybrid (`X25519MLKEM768`) and classical (`X25519`) probes against a TLS 1.3 endpoint via `openssl s_client -brief`, parses the negotiated group, and reports a readiness verdict.
- Output formats: Rich console (default; verdict panel + summary table + findings table + dependencies table; honors `NO_COLOR` per [no-color.org](https://no-color.org)) and JSON (machine-readable; locked top-level shape `qureddy.scan.v1`).
- Verbosity ladder: `-v` (INFO logs), `-vv` (DEBUG logs), `-vvv` (DEBUG + "Commands run" panel on stdout for traceability).
- Capability detection. `qureddy` checks the local OpenSSL binary for version 3.5+ and `X25519MLKEM768` group support before probing. Carries the detected `OpenSSLDependency` through exceptions to avoid re-probe.
- Retry policy. `--retry-on CATEGORIES --retries N --retry-delay SECONDS` for transient failures; allowlist gates which `FailureCategory` values are eligible (local-OpenSSL failures are never retryable).
- Exit codes. 0 (succeeded), 2 (target failed), 3 (local OpenSSL missing/unsupported), 4 (usage/configuration error). The `cli:main` wrapper translates Click `UsageError` to exit 4 so usage errors don't collide with target-failure (2).
- Target string parser. Accepts hostname, `host:port`, `https://` URLs, IPv4 literals, IPv6 bracketed literals. SNI auto-derived from hostname; required (`--sni`) for IP targets.
- Locked Pydantic model surface (`frozen=True, extra="forbid"`) for `ScanResult`, `ScanMetadata`, `ScanTarget`, `OpenSSLDependency`, `Asset`, `Evidence`, `ProbeCommand`, `ProbeResult`, `Finding`, `ScanSummary`. Top-level JSON keys are contractually ordered.
- Stderr classification. Maps OpenSSL nonzero exits to typed `FailureCategory` values: `target_connect_failed`, `tls_handshake_failed`, `sni_required_or_wrong`, `middlebox_or_mtu_failure`, `parse_no_group`, `parse_ambiguous`, `unexpected_group`.
- Structured logging via `structlog`. Logs to stderr (never stdout). Context vars (`scan_id`, `target`) propagate across modules. `--json-logs` for log-aggregator consumption; `--quiet` to suppress non-error logs.
- Quality-gate-clean CI surface: ruff (curated rule set with documented per-rule ignores), mypy --strict, bandit (MEDIUM threshold), pip-audit (HIGH/CRITICAL block; documented MODERATE ignore for `GHSA-58qw-9mgm-455v`), deptry, reuse lint, gitleaks. `pytest-rerunfailures` with 3 retries / 1s delay absorbs transient network flakes.
- Test suite: 186 unit tests + 6 live tests, 86%+ coverage. Includes regression tests for the no-double-probe property and the timeout partial-output preservation property.

### Repository scaffolding (pre-merged into 0.1.0 via main)

These landed during the pre-MVP phase and ship as part of 0.1.0:

- `pyproject.toml` with locked tool configs, `.gitattributes`, `.editorconfig`, `justfile`.
- Engineering standards: `docs/contributors/coding-rules.md` (full Python authoring rules + 7-phase CI + security bar + OpenSSF alignment).
- Agent contracts: `docs/contributors/agent-antipatterns.md`, `docs/contributors/agents/claude-developer-prompt.md`.
- Operational skills: `mvp-implement`, `audit-pr`, `write-test-fixture`, `run-quality-gates`.
- Code examples gallery: `docs/contributors/examples.md`.
- Test target catalog: `tests/fixtures/openssl/TARGETS.md`.
- REUSE compliance: `LICENSES/Apache-2.0.txt`, `REUSE.toml`, `.reuseignore`, SPDX headers on every source file.
- GitHub workflows: `ci.yml` (7-phase pipeline), `codeql.yml`, `scorecard.yml`, Dependabot config.
- Issue + PR templates: `.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`.

## [0.0.0] - 2026-04-26

Initial repository setup. Pre-MVP. No installable package. Superseded by 0.1.0 on the same day.

[Unreleased]: https://github.com/breachsafe/qureddy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/breachsafe/qureddy/releases/tag/v0.1.0
[0.0.0]: https://github.com/breachsafe/qureddy/releases/tag/v0.0.0
