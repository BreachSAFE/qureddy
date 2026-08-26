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
2. [0.9.0.3](#0903---2026-08-25)
3. [0.9.0.2](#0902---2026-08-25)
4. [0.9.0.1](#0901---2026-08-24)
5. [0.9.0.0](#0900---2026-08-24)

## Unreleased

### Changed

- Future changes will be recorded here until the next release is cut.

## [0.9.0.3] - 2026-08-25

### Fixed

- The release-signing verification job now installs the pinned Cosign version used
  by the build job and fails closed when cryptographic verification cannot run.
  This closes #502.

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
