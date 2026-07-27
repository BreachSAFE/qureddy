<!-- SPDX-License-Identifier: Apache-2.0 -->
---
name: Bug report
about: Something is broken or behaves unexpectedly
title: "[bug] "
labels: ["bug", "triage"]
assignees: []
---

## Summary

<!-- One sentence describing the bug. -->

## Severity

- [ ] **Security vulnerability** — STOP. Do not file a public issue. See [`SECURITY.md`](../../SECURITY.md) for the private disclosure process.
- [ ] Critical — scanner crashes, produces wrong findings, or silently fails
- [ ] High — scanner produces misleading output but does not crash
- [ ] Medium — feature works but is hard to use or under-documented
- [ ] Low — cosmetic, minor inconvenience

## Reproduction

**Command:**

```text
qureddy scan tls <target> --format json
```

**Steps:**

1.
2.
3.

**Expected:**

<!-- What you expected to happen. -->

**Actual:**

<!-- What actually happened. Paste the output below if relevant. -->

```text
<paste output here>
```

## Environment

- QuReddy version (commit SHA or release tag):
- Python version (`python --version`):
- OS and version:
- Scanner: TLS / SSH
- OpenSSL path and version for TLS (`openssl version`), or not applicable for SSH:
- Install method: `pipx` / virtual environment / editable source

## Logs

<!-- If running with `-v`, `-vv`, or `-vvv`, paste the relevant log lines.
     Do NOT paste secrets, full PEMs, or full subprocess output. Sanitize before posting. -->

```text
<paste sanitized logs>
```

## Anything else

<!-- Other context, screenshots, or related issues. -->
