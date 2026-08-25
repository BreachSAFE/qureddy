<!-- SPDX-FileCopyrightText: 2026 BreachSAFE QuReddy contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# QuReddy maintainers

This file records the people responsible for project decisions and release operations.
It is intentionally small: contribution does not require maintainer access.

## Current maintainer

| GitHub account | Responsibilities |
| --- | --- |
| [@paul007ex](https://github.com/paul007ex) | Project direction, code review, security-response coordination, release tagging, and TestPyPI/PyPI publishing |

## Review and release authority

- Changes to source, packaging metadata, CI, release workflows, or security policy require
  maintainer review.
- Releases are created from `main` after the repository release gate passes.
- Package publication uses GitHub Actions Trusted Publishing. Maintainers do not distribute
  long-lived PyPI API tokens to contributors.
- Security reports must follow [`SECURITY.md`](SECURITY.md), not a public issue.
- Maintainer responsibilities may be delegated by an explicit update to this file.

## Contributors

Contributors work through issues and pull requests. See [`CONTRIBUTING.md`](CONTRIBUTING.md)
for the development setup, review process, coding rules, and testing requirements.
