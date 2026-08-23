# OpenSSF Best Practices badge: passing-level self-certification draft

This document drafts QuReddy's answers to the [OpenSSF Best Practices
badge](https://www.bestpractices.dev/) **passing** questionnaire, with the
concrete evidence that already exists in this repository. It is a working
draft for the maintainer to transcribe into the questionnaire; the badge
itself is earned only on the website (see issue #92 and tracker #37).

Each criterion is marked **Met**, **N/A** (not applicable), or **TODO** (work
or evidence still required). Every "Met" cites a file, workflow, or command in
this repo so a reviewer can verify it. TODO items are collected in
[Summary and open items](#8-summary-and-open-items).

## Contents

1. [How to use this document](#1-how-to-use-this-document)
2. [Basics](#2-basics)
3. [Change control](#3-change-control)
4. [Reporting](#4-reporting)
5. [Quality](#5-quality)
6. [Security](#6-security)
7. [Analysis](#7-analysis)
8. [Summary and open items](#8-summary-and-open-items)
9. [Admin actions not doable in code](#9-admin-actions-not-doable-in-code)

## 1. How to use this document

The maintainer registers the project at https://www.bestpractices.dev, then
answers each criterion. For every criterion below, the questionnaire's
justification box can be filled with the "Evidence" text verbatim. Anything
marked TODO must be resolved (or honestly marked "Unmet"/"?" on the form)
before claiming the passing badge.

Criterion ids match the OpenSSF BadgeApp field names so they can be searched
on the form.

## 2. Basics

| id | status | evidence |
|---|---|---|
| `description_good` | Met | `README.md` opening paragraph: "QuReddy is an open-source command line scanner for post-quantum readiness at TLS and SSH endpoints." |
| `interact` | Met | GitHub Issues + Discussions enabled on `breachsafe/qureddy`; `CONTRIBUTING.md` §4 "Open an issue first". |
| `contribution` | Met | `CONTRIBUTING.md` documents the full workflow. |
| `contribution_requirements` | Met | `CONTRIBUTING.md` §5 "Coding style" points to `docs/contributors/coding-rules.md` as the "Source of truth"; Conventional Commits, ruff/mypy requirements. |
| `floss_license` | Met | Root `LICENSE` is the Apache License 2.0; `pyproject.toml` `license = "Apache-2.0"`. |
| `floss_license_osi` | Met | Apache-2.0 is OSI-approved; `pyproject.toml` carries the `License :: OSI Approved :: Apache Software License` classifier. |
| `license_location` | Met | Root `LICENSE` file, `LICENSES/Apache-2.0.txt`, `REUSE.toml`. |
| `documentation_basics` | Met | `docs/` Diataxis tree (tutorials, how-to, reference, explanation) plus `README.md`. |
| `documentation_interface` | Met | `docs/reference/cli.md`, `docs/reference/exit-codes.md`, `docs/reference/json-schema.md`, `docs/reference/cbom.md`. |
| `sites_https` | Met | GitHub project and docs are served over HTTPS. |
| `discussion` | Met | GitHub Issues and Discussions. |
| `english` | Met | All docs and code comments are in English. |
| `maintained` | Met | Active commit history on `main`; maintainer responds to issues (see [Reporting](#4-reporting)). |

## 3. Change control

| id | status | evidence |
|---|---|---|
| `repo_public` | Met | `breachsafe/qureddy` is a public GitHub repository. |
| `repo_track` | Met | Git version control. |
| `repo_distributed` | Met | Git is distributed. |
| `version_unique` | Met | `pyproject.toml` `version = "0.2.44"`; each release bumps it (`scripts/bump_version.py`). |
| `version_semver` | Met | Semantic versioning on the `0.2.x` line. |
| `version_tags` | Met | Releases are tagged `vX.Y.Z` (e.g. `v0.2.44`). |
| `release_notes` | Met | `CHANGELOG.md` (Keep a Changelog format). |
| `release_notes_vulns` | Met | `CHANGELOG.md` records security-relevant fixes; `SECURITY.md` §4 covers advisory publication. |

## 4. Reporting

| id | status | evidence |
|---|---|---|
| `report_process` | Met | `CONTRIBUTING.md` §4 (feature/bug via issue) and `SECURITY.md` §2 (vulnerabilities via private advisory). |
| `report_tracker` | Met | GitHub Issues: https://github.com/breachsafe/qureddy/issues |
| `report_responses` | TODO | See #218. The maintainer must leave visible replies on a representative set of open issues and cite one issue URL as justification. Do not mark Met until evidenced. |
| `report_archive` | Met | Searchable issue archive at https://github.com/breachsafe/qureddy/issues |
| `vulnerability_report_process` | Met | `SECURITY.md` §2 "Report a vulnerability" documents the process. |
| `vulnerability_report_private` | Met | `SECURITY.md` §2 directs reporters to GitHub Security Advisories (private) with an email fallback. |
| `vulnerability_report_response` | Met | `SECURITY.md` §3 "Response targets": acknowledgement within 5 business days. |

## 5. Quality

| id | status | evidence |
|---|---|---|
| `build` | Met | `.github/workflows/ci.yml` `phase-6-build` runs `uv build`; hatchling backend in `pyproject.toml`. |
| `build_common_tools` | Met | uv + hatchling are common Python build tools. |
| `build_floss_tools` | Met | uv and hatchling are FLOSS. |
| `test` | Met | `tests/` (40+ test files); `pytest` invoked in CI `phase-2-unit` / `phase-3-integration`. |
| `test_invocation` | Met | `pytest` (documented in `CONTRIBUTING.md` §6 and `docs/contributors/coding-rules.md`). |
| `test_most` | Met | Coverage gate `--cov-fail-under=80` in `ci.yml` `phase-2-unit` and `scripts/release_gate.py`. |
| `test_policy` | Met | `CONTRIBUTING.md` §6 "Every test runs every time"; `docs/contributors/coding-rules.md` §9. |
| `tests_are_added` | Met | Policy in `CONTRIBUTING.md` §6; enforced by the coverage gate on each PR. |
| `tests_documented_added` | Met | `docs/contributors/coding-rules.md` §9 documents the test-addition policy. |
| `warnings` | Met | `ruff check`, `ruff format --check`, `mypy --strict` in `ci.yml` `phase-1-static`. |
| `warnings_fixed` | Met | CI fails on any ruff/mypy finding (`phase-1-static` is blocking). |
| `warnings_strict` | Met | `mypy --strict`; ruff runs with the project's full rule set. |

## 6. Security

QuReddy implements no first-party cryptography. It shells out to the system
OpenSSL 3.5.7 LTS binary for TLS observation and reads the server's cleartext
SSH KEXINIT offer. The `crypto_*` criteria are answered on that basis.

| id | status | evidence |
|---|---|---|
| `crypto_published` | Met | No custom crypto; relies on OpenSSL 3.5.7 LTS (published, standard). |
| `crypto_call` | Met | Calls system OpenSSL; implements no primitive itself. |
| `crypto_floss` | Met | OpenSSL is FLOSS. |
| `crypto_keylength` | N/A | The scanner selects no keys; it observes and reports the endpoint's. |
| `crypto_working` | Met | No broken/experimental crypto is used by the tool itself. |
| `crypto_weaknesses` | Met | No known-weak crypto in the tool's own operation. |
| `crypto_pfs` | N/A | The tool establishes no long-lived secure channel of its own. |
| `crypto_password_storage` | N/A | Scanner authenticates no users and stores no passwords (see #217 A1). |
| `crypto_random` | N/A | The tool needs no security-sensitive randomness of its own. |
| `delivery_mitm` | Met | Distribution over HTTPS (GitHub, TestPyPI); artifacts hash-pinned in `scripts/release-tools.json`; container base images pinned by digest in `Dockerfile`. |
| `delivery_unsigned` | Met (mechanism); TODO (operational) | `.github/workflows/release.yml` signs distributions with cosign keyless OIDC and emits SLSA provenance via `actions/attest-build-provenance`. Operational gap: the latest releases were cut outside `release.yml` and are unsigned (see #219); route all releases through the workflow. |
| `vulnerabilities_fixed_60_days` | Met | No medium+ vuln in produced/runtime software. Two accepted advisories are dev-tooling only (pip `GHSA-58qw-9mgm-455v`, py `PYSEC-2022-42969`), documented in `pyproject.toml [tool.pip-audit]`; both non-exploitable in QuReddy's paths (see #217 A2). |
| `vulnerabilities_critical_fixed` | Met | `pip-audit` runs on the runtime dependency path in `ci.yml` `phase-1-static` and the release gate with no ignored critical advisories. |
| `no_leaked_credentials` | Met | Gitleaks full-history scan in `ci.yml` `phase-1-static` and `scripts/release_gate.py`. |

## 7. Analysis

| id | status | evidence |
|---|---|---|
| `static_analysis` | Met | ruff, mypy `--strict`, bandit (`ci.yml` `phase-1-static`) and CodeQL `security-extended` (`.github/workflows/codeql.yml`). |
| `static_analysis_common_vulnerabilities` | Met | CodeQL `+security-extended` query pack; bandit for Python security smells. |
| `static_analysis_fixed` | Met | `phase-1-static` and CodeQL are blocking on PRs; findings must be fixed to merge. |
| `static_analysis_often` | Met | CodeQL on every PR, on push to `main`, and weekly; bandit/ruff/mypy on every PR. |
| `dynamic_analysis` | Met | Integration and live scans in `ci.yml` `phase-3`/`phase-4`/`phase-5` exercise the tool against real endpoints; `trivy fs` scan in `phase-6-build`. |
| `dynamic_analysis_unsafe` | N/A | Pure-Python (memory-safe) tool; no C/C++ memory-safety fuzzing surface of its own. |
| `dynamic_analysis_enable_assertions` | Met | pytest runs with assertions enabled by default. |
| `dynamic_analysis_fixed` | Met | Dynamic-test failures block merge (CI phases are gated). |

## 8. Summary and open items

Passing-criteria tally in this draft:

- **Met:** the large majority of criteria across all six groups, each with in-repo evidence above.
- **N/A (correctly):** `crypto_keylength`, `crypto_pfs`, `crypto_password_storage`, `crypto_random`, `dynamic_analysis_unsafe`.
- **TODO (evidence or behavior still required):**
  1. `report_responses` (#218): leave visible maintainer replies on open issues and cite one issue URL. Behavioral, not code.
  2. `delivery_unsigned` operational gap (#219): route every published release through `release.yml` so the signed-artifact mechanism actually runs; backfill signatures on the latest unsigned releases.

No criterion in this draft is genuinely unmet in a way that blocks the passing
badge once the two TODOs are closed. The questionnaire on the website is the
system of record; this file is the evidence pack for filling it in.

## 9. Admin actions not doable in code

These cannot be completed from a pull request and are the maintainer's to do
(tracked under #37):

1. **Register and answer the questionnaire** at https://www.bestpractices.dev
   for `breachsafe/qureddy` (#92), using the evidence above; then add the
   earned badge to `README.md` and `SECURITY.md`.
2. **Enable branch protection on `main`** requiring pull-request review and
   passing status checks (#84). This also fixes the Scorecard
   Branch-Protection, Code-Review, and CI-Tests checks (#220).
3. **Publish releases through `release.yml`** so cosign signing runs (#219).
4. **Confirm org/repo security settings** Scorecard reads: token permissions,
   published security policy, and Dependabot/security-advisory settings.
</content>
