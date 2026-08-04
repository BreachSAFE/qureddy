# Contributing to QuReddy

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?style=flat-square&logo=conventionalcommits&logoColor=white)](https://www.conventionalcommits.org)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-D7FF64?style=flat-square&logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![Type Checked: mypy strict](https://img.shields.io/badge/type%20check-mypy%20strict-blue?style=flat-square)](https://mypy-lang.org/)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen?style=flat-square)](pyproject.toml)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/license-PolyForm%20Noncommercial-orange?style=flat-square)](LICENSE)

Thanks for considering a contribution. This document covers what you need to know.

## Contents

- [Before you contribute](#before-you-contribute)
- [Project state](#project-state)
- [Set up a development environment](#set-up-a-development-environment)
- [Workflow](#workflow)
- [Coding style](#coding-style)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [Security](#security)
- [Commits](#commits)
- [License](#license)
- [Code of Conduct](#code-of-conduct)

## Before you contribute

Read these in order:

1. [`README.md`](README.md); what QuReddy is and what state it's in.
2. [`docs/explanation/architecture.md`](docs/explanation/architecture.md); project orientation and settled architecture.
3. [`docs/contributors/coding-rules.md`](docs/contributors/coding-rules.md); engineering standards. **Source of truth.** Read fully before writing code.
4. [`docs/contributors/examples.md`](docs/contributors/examples.md); good-vs-bad code patterns. Read before writing the first file in a new module.

## Project state

QuReddy 0.2.0 ships TLS and SSH scanners with Rich, JSON, and CycloneDX 1.7
CBOM output. Certificate signature observation and legacy TLS enumeration are
part of the TLS scan. Full certificate chain analysis, config scanning, source
scanning, hosted operation, and remediation are not shipped.

The current milestone is named in [`docs/reference/milestones.md`](docs/reference/milestones.md).

## Set up a development environment

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

You also need OpenSSL 3.5 LTS or newer on your `PATH` for the TLS scanner to work end-to-end:

- macOS: `brew install openssl@3.5` (the OpenSSL 3.5 LTS line)
- Linux: use a supported vendor build or the official OpenSSL source
- Windows: install a trusted OpenSSL 3.5 LTS or newer build and set its path

QuReddy's capability check exits 3 with a clear message when OpenSSL is missing or too old.

## Workflow

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

## Coding style

Read `docs/contributors/coding-rules.md` and `docs/contributors/examples.md`. The short version:

- Python 3.12, typed (`mypy --strict`), formatted (`ruff format`), linted (`ruff check`)
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

## Testing

Per `docs/contributors/coding-rules.md` Section 9:

- Every test runs every time. No `@pytest.mark.skip`, no `@pytest.mark.acceptance`.
- Network-dependent tests live in `tests/live/` and run on default `pytest`. `pytest-rerunfailures` absorbs hiccups.
- Coverage minimum is 80%.
- Fixtures under `tests/fixtures/` use real captured outputs, not synthetic stubs.

## Dependencies

Adding a runtime dependency requires PR justification per Rule 13.1:

- Replaces ≥ 50 lines of code we would have written
- Actively maintained (commit in last 12 months)
- License and distribution terms compatible with PolyForm Noncommercial; preserve all upstream notices
- Recognizable maintainer

GPL, AGPL, and LGPL dependencies do not meet the documented dependency policy.
Reviewers verify license compatibility before accepting a runtime dependency;
the current CI does not automate that decision with `pip-licenses`.

## Security

If you find a vulnerability, **do not open a public issue.** See [`SECURITY.md`](SECURITY.md) for the disclosure process.

Insecure shortcuts are forbidden in PRs (Rule 26.13). If you need to disable TLS verification, log secrets, use `shell=True`, or take any other insecure shortcut, the PR will be rejected. The right answer is a captured fixture, list-form arguments, or hash-only logging.

## Commits

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

## License

By contributing, you confirm that you have authority to contribute the material and agree that your contribution is licensed under the PolyForm Noncommercial License 1.0.0. Every first-party source file must have an SPDX header:

```python
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
```

`reuse lint` enforces this in CI.

## Code of Conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). The short version: be respectful, assume good faith, focus on the code.
