# Plan 0001 — PyPI launch

**Status:** Superseded by public release issues
**Date:** 2026-04-26
**Owner:** Paul Volosen
**Superseded by:** [public issues #30–#36](https://github.com/breachsafe/qureddy/issues)

> Historical plan. It records the original launch thinking, but its version,
> issue-number, workflow-action, and release-authority details are not current.
> Use public issues #30–#36 for the first-PyPI-release gate and sequence.

## Contents

- [Why a plan](#why-a-plan-not-an-issue)
- [Pre-launch gate](#pre-launch-gate-the-rock-solid-bar)
- [Phase 1: Name reservation](#phase-1--name-reservation-do-today-low-cost)
- [Phase 2: Trusted Publisher](#phase-2--trusted-publisher-oidc-setup-30-min)
- [Phase 3: Release workflow](#phase-3--release-workflow-1-hour)
- [Phase 4: Pre-publish dry run](#phase-4--pre-publish-dry-run-30-min)
- [Phase 5: Production publish](#phase-5--production-publish-10-min-once-gates-clear)
- [Phase 6: Launch window](#phase-6--launch-window-1-day-all-in-one-focused-session)
- [Phase 7: Post-launch monitoring](#phase-7--post-launch-monitoring-first-2-weeks)
- [Risks and mitigations](#risks-and-mitigations)
- [Pending decisions](#decisions-still-pending)
- [Acceptance criteria](#acceptance-criteria-for-this-plan)
- [Related documentation](#related-documentation)

## Why a plan, not an issue

Publishing to PyPI is the project's first public-installability event. It's irreversible (every version stays on PyPI forever), it sets first impressions for every operator who `pip install`s the tool, and it touches code, docs, infra, and external outreach. That's plan-shaped, not issue-shaped.

This document is the canonical reference for the launch. Issues track individual tasks; this doc explains how they connect.

## Pre-launch gate (the "rock-solid" bar)

The launch does not happen until **every one of these is true**:

- [ ] All 19 known bug issues closed (#7, #8, #9, #10, #11, #12, #13, #14, #15, #16, #17, #18, #19, #21, #22, #23, #24, #25 — plus any new ones filed in the meantime)
- [ ] CI honestly green — `continue-on-error: true` removed from `.github/workflows/ci.yml`, all phases must pass for real
- [ ] Test coverage stays ≥ 80% (currently 86%)
- [ ] Fresh-clone verification passes on macOS, Linux, Windows (CI matrix already does this; verify after bug fixes don't regress)
- [ ] One round of "scan 100 random Top-Sites" smoke test — no bizarre verdicts, no crashes, no malformed output
- [ ] OSS/Enterprise framing locked (ADR 0004 + 2 docs) so PyPI page tells the right story
- [ ] `--help` rewrite landed (ADR 0003) so first-time-installer impression is professional
- [ ] CHANGELOG.md entry for the launch version is final
- [ ] `pyproject.toml` metadata audited: description accurate, classifiers correct, all `[project.urls]` reachable

## Phase 1 — Name reservation (do today, low cost)

Even though we're not launching yet, the package name needs to be secured so nobody else grabs `breachsafe-qureddy` first. Two accounts, two registrations.

| Step | What | Cost |
|---|---|---|
| 1.1 | Create PyPI account at https://pypi.org/account/register/ | free |
| 1.2 | Enable 2FA on the account (mandatory for publishing since 2024) | free |
| 1.3 | Create TestPyPI account at https://test.pypi.org/account/register/ (separate account) | free |
| 1.4 | Enable 2FA on TestPyPI account | free |
| 1.5 | Decide whether to upload a placeholder v0.0.0 to reserve the name now, or rely on first real publish to claim it | — |

**Recommendation on 1.5:** Don't upload a placeholder. PyPI versions are permanent. Reserve the name implicitly by being first to publish v0.1.x, after the rock-solid gate is met. The name `breachsafe-qureddy` is currently unowned — the risk of someone else racing is low for an obscure name.

If you want belt-and-suspenders: upload the actual built `0.1.0` artifacts but mark them as a yanked release (`twine upload` + yank via the PyPI web UI) so nobody installs them. Slightly weird, probably overkill.

## Phase 2 — Trusted Publisher OIDC setup (~30 min)

Instead of an API token sitting in a GitHub secret, PyPI lets you authorize publishes via OIDC tied to a specific GitHub repo + workflow. This is the modern best practice.

| Step | What |
|---|---|
| 2.1 | On pypi.org, navigate to the project (after first publish or use "pending publisher" pre-publish) |
| 2.2 | Add a Trusted Publisher: GitHub \| owner: breachsafe \| repo: qureddy \| workflow: release.yml \| environment: pypi |
| 2.3 | Repeat on test.pypi.org for the testpypi environment |
| 2.4 | Documentation: https://docs.pypi.org/trusted-publishers/ |

Outcome: the `release.yml` workflow can publish without any stored token. PyPI badge on the project shows "Verified" for releases through this path.

## Phase 3 — Release workflow (~1 hour)

Add `.github/workflows/release.yml` triggered on git tags matching `v*.*.*`:

```yaml
name: Release
on:
  push:
    tags: ['v*.*.*']
  workflow_dispatch:
permissions:
  id-token: write       # OIDC for Trusted Publisher
  contents: read
jobs:
  build-and-publish:
    runs-on: ubuntu-latest
    environment: pypi   # required for OIDC
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - uses: astral-sh/setup-uv@v3
      - run: uv build
      - uses: pypa/gh-action-pypi-publish@release/v1
```

For a separate TestPyPI dry-run workflow, same shape but with `repository-url: https://test.pypi.org/legacy/` and a different environment (`testpypi`).

| Step | What |
|---|---|
| 3.1 | Write `.github/workflows/release.yml` (production publish on tag push) |
| 3.2 | Write `.github/workflows/release-testpypi.yml` (TestPyPI publish on `workflow_dispatch` for dry runs) |
| 3.3 | Add a `pypi` environment in repo Settings → Environments with required reviewers (= you) so a tag push doesn't auto-publish without manual approval |
| 3.4 | Test the TestPyPI workflow on `workflow_dispatch` once everything else is ready |

## Phase 4 — Pre-publish dry run (~30 min)

Before the real upload, exercise the full path on TestPyPI:

| Step | What |
|---|---|
| 4.1 | `uv build` locally; `uvx twine check dist/*` to verify metadata renders |
| 4.2 | Trigger the TestPyPI release workflow |
| 4.3 | `pipx install --index-url https://test.pypi.org/simple/ breachsafe-qureddy` from a clean machine (or fresh container) |
| 4.4 | Run `qureddy scan tls www.google.com` — verify it works |
| 4.5 | Open https://test.pypi.org/project/breachsafe-qureddy/ in a browser — verify README renders, links work, no broken images, classifiers are right |
| 4.6 | Note any rendering quirks; fix in a follow-up commit before real publish |

## Phase 5 — Production publish (~10 min once gates clear)

| Step | What |
|---|---|
| 5.1 | Confirm pre-launch gate is fully green |
| 5.2 | `git tag v0.1.0 -a -m "v0.1.0 — initial PyPI release"` |
| 5.3 | `git push --tags` |
| 5.4 | Approve the production release workflow in the GitHub Actions UI |
| 5.5 | Verify https://pypi.org/project/breachsafe-qureddy/ |
| 5.6 | `pipx install breachsafe-qureddy` from a fresh shell, verify end-to-end |
| 5.7 | Create a GitHub Release pointing at the tag, paste CHANGELOG entry as release notes, attach the wheel + sdist |

## Phase 6 — Launch window (~1 day, all in one focused session)

The launch announcement is more leverage than the publish itself. Do these in one focused window:

| Step | Audience | Effort |
|---|---|---|
| 6.1 | **Show HN post** — title: "Show HN: QuReddy — open-source post-quantum TLS readiness scanner" — link to GitHub repo, attach screenshot of `qureddy scan tls www.google.com -vvv` | 30 min |
| 6.2 | Be ready to answer questions in the HN thread for 4-6 hours after posting | 4-6 hours |
| 6.3 | Cross-post to /r/cryptography (Reddit) | 15 min |
| 6.4 | Cross-post to /r/netsec | 15 min |
| 6.5 | Submit to lobste.rs (need an existing account or invitation) | 15 min |
| 6.6 | Email the IETF TLS WG mailing list — 2-paragraph friendly intro | 30 min |
| 6.7 | Email Cloudflare Research PQ team (the people whose endpoints you scan) — "I built this against your work, here's the JSON output, are the verdicts right?" | 30 min |
| 6.8 | Email Google Chrome / BoringSSL team (same framing) | 30 min |
| 6.9 | Tweet / post on personal accounts | 15 min |

Best timing per Hacker News convention: Tuesday-Thursday morning Pacific (12:00-15:00 UTC).

## Phase 7 — Post-launch monitoring (first 2 weeks)

| Step | What |
|---|---|
| 7.1 | Watch GitHub issues; respond within 24h to first 10 issues |
| 7.2 | Watch download stats on https://pypistats.org/packages/breachsafe-qureddy |
| 7.3 | Watch PyPI security alerts (via 2FA email) |
| 7.4 | Monitor for typo-squat packages — file PyPI report if "breechsafe-qureddy" or similar appears |
| 7.5 | If a real bug surfaces, fix it and ship v0.1.1 within 48h. Speed signals seriousness. |
| 7.6 | Apply for OpenSSF Best Practices Badge (passing tier) — https://www.bestpractices.dev/ |

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Name `breachsafe-qureddy` is taken when we go to register | Check pypi.org today; have a fallback name ready (e.g. `qureddy`, `breachsafe-pqc`) |
| First release ships with a bug we missed | Plan v0.1.1 within 48h; pin a public commitment to fast bug-fix cycles in CONTRIBUTING.md |
| Show HN front-pages and we get 100+ issues in a day | Pre-write triage labels; route obvious dupes to an existing umbrella issue |
| Show HN drops to page 5 with no engagement | Have a backup post at /r/cryptography ready; the launch isn't dead, just the channel |
| OpenSSF badge application fails | The badge is *iterative* — apply, fix what they flag, reapply. Failure isn't terminal. |
| `pip install` works but `qureddy` not on PATH | Document `pipx install` as primary path; provide explicit troubleshooting in tutorial |
| Dependency CVE breaks the install | pip-audit gate already catches this in CI; resolve before tagging |

## Decisions still pending

These need answers before Phase 5:

| Decision | Options |
|---|---|
| First public version number | `v0.1.0` (current MVP version, but launches dirty) vs `v0.1.1` (clean post-bug-fix) vs `v0.2.0` (if cert scanner ships first) |
| Use TestPyPI? | Yes (recommended) vs No (faster, riskier) |
| Pre-launch announcement to maintainer-adjacent network? | Yes (build buzz) vs No (let the launch be the announcement) |
| Should the `pypi` environment require manual approval? | Yes (recommended — tag pushes don't auto-publish) vs No (faster) |
| Submit to PyPI Trove classifiers for compliance/regulated industries? | Decide what classifiers to add (`Topic :: Security :: Cryptography` is already there; consider also `Operating System :: OS Independent`, `Environment :: Console`) |

## Acceptance criteria for this plan

This plan is "done" when:

- [ ] v0.1.x is published on PyPI
- [ ] `pipx install breachsafe-qureddy` works on macOS, Linux, Windows
- [ ] Show HN post is up
- [ ] At least one external party has acknowledged the launch (HN comment, retweet, email reply)
- [ ] The first 5 GitHub issues from external users are responded to within 24h

## Related documentation

- [PyPI documentation](https://docs.pypi.org/)
- [Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [OpenSSF Best Practices](https://www.bestpractices.dev/)
- [`docs/reference/milestones.md`](../../reference/milestones.md) — where this lands in the broader roadmap
- [`docs/contributors/coding-rules.md`](../coding-rules.md) — quality bar this launch must meet
