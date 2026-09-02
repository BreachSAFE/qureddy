# Contributing to QuReddy

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?style=flat-square&logo=conventionalcommits&logoColor=white)](https://www.conventionalcommits.org)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-D7FF64?style=flat-square&logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![Type Checked: mypy strict](https://img.shields.io/badge/type%20check-mypy%20strict-blue?style=flat-square)](https://mypy-lang.org/)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen?style=flat-square)](pyproject.toml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)

Thanks for considering a contribution. This document covers what you need to know.

## Contents

1. [Before you contribute](#1-before-you-contribute)
2. [Project state](#2-project-state)
3. [Set up a development environment](#3-set-up-a-development-environment)
4. [Workflow](#4-workflow)
5. [Coding style](#5-coding-style)
6. [Testing](#6-testing)
7. [Dependencies](#7-dependencies)
8. [Security](#8-security)
9. [Commits](#9-commits)
10. [License](#10-license)
11. [Code of Conduct](#11-code-of-conduct)
12. [Maintainers](#12-maintainers)

## 1. Before you contribute

Read these in order:

1. [`README.md`](README.md); what QuReddy is and what state it's in.
2. [`docs/explanation/architecture.md`](docs/explanation/architecture.md); project orientation and settled architecture.
3. [`docs/contributors/coding-rules.md`](docs/contributors/coding-rules.md); engineering standards. **Source of truth.** Read fully before writing code.
4. [`docs/contributors/examples.md`](docs/contributors/examples.md); good-vs-bad code patterns. Read before writing the first file in a new module.
5. [`MAINTAINERS.md`](MAINTAINERS.md); review and release authority.

## 2. Project state

QuReddy ships TLS, SSH, and stock `ike-scan` backed IKE scanners with Rich,
JSON, JSONL, and CycloneDX 1.7 CBOM output. Certificate signature observation
and legacy TLS enumeration are part of the TLS scan. IKE observations are
lower-trust discovery evidence and do not prove an authenticated tunnel. Full
certificate chain analysis, config scanning, source scanning, hosted operation,
and remediation are not shipped.

The current milestone is named in [`docs/reference/milestones.md`](docs/reference/milestones.md).

## 3. Set up a development environment

```bash
# Clone
git clone https://github.com/breachsafe/qureddy.git
cd qureddy

# Install uv if you don't have it
# https://github.com/astral-sh/uv

# Create the dev environment
just setup
# Or manually:
uv venv
uv pip install -e ".[dev]"

# Install pre-commit hooks (one-time, per docs/contributors/coding-rules.md §23)
uv run pre-commit install

# Verify
uv run qureddy --help
just gates               # runs the full Tier 1 gate suite
just hooks               # runs pre-commit hooks against all files (CI-equivalent local check)
```

You also need OpenSSL 3.5.7 LTS on your `PATH` for the TLS scanner to work end-to-end:

- macOS: `brew install openssl@3.5` (the OpenSSL 3.5 LTS line)
- Linux: use a supported vendor build or the official OpenSSL source
- Windows: install a trusted OpenSSL 3.5.7 LTS build and set its path

QuReddy's capability check exits 3 with a clear message when OpenSSL is missing or too old.

Install stock `ike-scan` separately to run the live IKE path. QuReddy invokes
the executable at runtime and does not distribute or link its GPL-licensed code.

## 4. Workflow

1. **Open an issue first** for non-trivial changes. We will tell you if it's in scope for the current milestone before you write code.
2. **Branch from `main`**. Branch naming: `<type>/<short-description>` (e.g., `feat/cert-scanner`, `fix/openssl-version-parse`).
3. **One thing per PR.** Per Rule 1.3 in CODING_RULES, do not bundle a refactor with a feature with a bug fix. If your PR description splits into "Part 1" and "Part 2," it should be two PRs.
4. **Run the gates locally** before pushing:

   ```
   just gates
   ```

5. **Open a PR.** Fill out the PR template. The audit checklist is non-negotiable.
6. **Self-review your own diff.** The `audit-pr` skill output goes in the PR description.
7. **CI must pass on all three platforms** (ubuntu, macos, windows) before merge.
8. **Squash-and-merge** is the default merge strategy.

Before release work, run the repository-owned local gate:

```bash
just release-gate
```

The gate builds and audits exact wheel and source distribution bytes. See the
[local release gate](docs/contributors/local-release-gate.md).

## 5. Coding style

Read `docs/contributors/coding-rules.md` and `docs/contributors/examples.md`. The short version:

- Python 3.14, typed (`mypy --strict`), formatted (`ruff format`), linted (`ruff check`)
- Functions ≤ 30 lines normal, 50 ceiling
- Files ≤ 300 lines normal, 400 ceiling
- Classes ≤ 200 lines
- Pydantic models frozen by default with `extra="forbid"`
- `tuple[X, ...]` over `list[X]` unless mutation is required
- Specific exceptions, not bare `except` or broad `except Exception`
- Subprocess: list-form args, explicit `timeout`, `shell=False`
- Structured logging with k/v pairs, never f-strings
- All datetimes timezone-aware UTC
- SPDX header on every source file

## 6. Testing

Per `docs/contributors/coding-rules.md` Section 9:

- Every test runs every time. No `@pytest.mark.skip`, no `@pytest.mark.acceptance`.
- Network-dependent tests live in `tests/live/` and run on default `pytest`. `pytest-rerunfailures` absorbs hiccups.
- Coverage minimum is 90%.
- Fixtures under `tests/fixtures/` use real captured outputs, not synthetic stubs.

## 7. Dependencies

Adding a runtime dependency requires PR justification per Rule 13.1:

- Replaces ≥ 50 lines of code we would have written
- Actively maintained (commit in last 12 months)
- License and distribution terms compatible with Apache-2.0; preserve all upstream notices
- Recognizable maintainer

GPL, AGPL, and LGPL dependencies do not meet the documented dependency policy.
Reviewers verify license compatibility before accepting a runtime dependency;
the current CI does not automate that decision with `pip-licenses`.
The optional stock `ike-scan` program is a separately installed executable, not
a linked or distributed Python runtime dependency.

## 8. Security

If you find a vulnerability, **do not open a public issue.** See [`SECURITY.md`](SECURITY.md) for the disclosure process.

Insecure shortcuts are forbidden in PRs (Rule 26.13). If you need to disable TLS verification, log secrets, use `shell=True`, or take any other insecure shortcut, the PR will be rejected. The right answer is a captured fixture, list-form arguments, or hash-only logging.

## 9. Commits

Conventional Commits format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types we use: `feat`, `fix`, `docs`, `test`, `refactor`, `build`, `ci`, `chore`, `perf`, `security`.

Examples:

- `feat(scanner): add TLS 1.3 hybrid probe`
- `fix(parser): reject ClientHello-only X25519MLKEM768`
- `docs(coding-rules): clarify retry allowlist`

## 10. License

By contributing, you confirm that you have authority to contribute the material and agree that your contribution is licensed under the Apache License 2.0. Every first-party source file must have an SPDX header:

```python
# SPDX-License-Identifier: Apache-2.0
```

`reuse lint` enforces this in CI.

## 11. Code of Conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). The short version: be respectful, assume good faith, focus on the code.

## 12. Maintainers

[`MAINTAINERS.md`](MAINTAINERS.md) identifies the current project maintainer and the
review and release responsibilities that require maintainer approval. The repository's
[`CODEOWNERS`](.github/CODEOWNERS) file routes changes to the maintainer automatically.

Contributors do not need package-publishing credentials. Releases are built and published
by the protected GitHub Actions release workflow after review and the repository release
gate pass.
