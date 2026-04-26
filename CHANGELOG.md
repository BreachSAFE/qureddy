# Changelog

[![Status: Pre-MVP](https://img.shields.io/badge/status-pre--MVP-orange?style=flat-square)](docs/mvp/CURRENT.md)
[![Version](https://img.shields.io/badge/version-0.0.0--dev-lightgrey?style=flat-square)](CHANGELOG.md)
[![Keep a Changelog](https://img.shields.io/badge/keep%20a%20changelog-1.1.0-orange?style=flat-square)](https://keepachangelog.com/en/1.1.0/)
[![SemVer](https://img.shields.io/badge/SemVer-2.0.0-blue?style=flat-square)](https://semver.org/spec/v2.0.0.html)

All notable changes to QuReddy are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). QuReddy uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

OpenSSF Best Practices Badge target: passing tier by MVP 0.6, silver by v1.0.

## [Unreleased]

### Added

- Repository scaffolding: `pyproject.toml` with locked tool configs, `.gitattributes`, `.editorconfig`, `justfile`.
- Engineering standards: `docs/CODING_RULES.md` (full Python authoring rules + 7-phase CI + security bar + OpenSSF alignment).
- Agent contracts: `docs/AGENT_ANTIPATTERNS.md`, `docs/CLAUDE_DEVELOPER_PROMPT.md`.
- Operational skills: `mvp-implement`, `audit-pr`, `write-test-fixture`, `run-quality-gates`.
- Code examples gallery: `docs/EXAMPLES.md` (Pydantic models, tests, subprocess, logging, exceptions, docstrings, CLI, JSON output).
- MVP 0.1 implementation prompt and bootstrap.
- Test target catalog: `tests/fixtures/openssl/TARGETS.md`.

### Changed

- (No version-tagged changes yet.)

### Deprecated

### Removed

### Fixed

### Security

## [0.0.0] - 2026-04-26

Initial repository setup. Pre-MVP. No installable package.

[Unreleased]: https://github.com/paul007ex/qureddy/compare/v0.0.0...HEAD
[0.0.0]: https://github.com/paul007ex/qureddy/releases/tag/v0.0.0
