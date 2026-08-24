<!-- markdownlint-disable MD022 MD025 MD026 -->
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# QuReddy repository guidance for Claude Code and other coding agents.
<!-- markdownlint-enable MD022 MD025 MD026 -->

## Contents

1. [Instruction hierarchy](#instruction-hierarchy)
2. [Deliberate QuReddy divergences](#deliberate-qureddy-divergences)
3. [Temporary workspace policy](#temporary-workspace-policy)
4. [Change procedure](#change-procedure)

## Instruction hierarchy

Read and apply these sources in order:

1. **`~/claude/CLAUDE.md` (platform guidance).** This is the BQP-wide contract for
   licensing, canonical repositories, Python/OpenSSL baselines, worktree and PR
   procedure, and cross-repository architecture. It is auto-loaded because Claude
   Code walks up from the working directory. Platform policy remains authoritative
   for cross-repo and safety rules; record any deliberate repo exception below.
2. **This file (QuReddy guidance).** These are rules specific to this repository.
   They refine, but do not silently weaken, the platform contract.
3. **`AGENTS.md` (QuReddy operating card).** This records the numbered ten-step
   development process and fast command path. Follow it in order and mark skipped
   steps `NOT RUN` with a reason.
4. **Task-scoped skills under `.claude/skills/` and the installed BreachSAFE skill
   library.** Use the narrowest applicable skill and follow its audit/implementation
   boundary. If a skill conflicts with platform or repository guidance, stop and
   resolve the conflict explicitly.

## Deliberate QuReddy divergences

- **License:** QuReddy is an Apache-2.0 repository. Do not apply the platform
  PolyForm default to existing QuReddy source or new QuReddy-owned files without a
  reviewed licensing decision; preserve third-party notices and run `reuse lint`.
- **Canonical source:** only `github.com/breachsafe/qureddy` is authoritative. Do not
  use similarly named personal or legacy repositories for source, release, or issue
  decisions.
- **Distribution:** TestPyPI is the only Python package index in scope for the
  foreseeable future. Releases publish to TestPyPI only. Production PyPI is out of
  scope: do not probe it, publish to it, or treat a production PyPI 404 as a failure.
- **Runtime baseline:** Python commands, hooks, environments, and CI use Python 3.14+
  everywhere, and native
  OpenSSL validation uses the pinned 3.5.7 LTS contract.
- **SSH scope:** the SSH acquisition redesign and `ssh-audit` work remain parked in
  the 0.5.0 backlog unless a maintainer explicitly changes that scope.

## Temporary workspace policy

All QuReddy temporary worktrees, pressure-test outputs, build artifacts, and disposable
logs MUST use the RAM-backed workspace when it is mounted:

```bash
export TMPDIR=/Volumes/ramlogs/tmp/qureddy
mkdir -p "$TMPDIR"
chmod 700 "$TMPDIR"
```

Check free space before large runs. Keep the canonical checkout, Git history, credentials,
virtual environments, and irreplaceable artifacts on persistent storage. Do not replace,
symlink, or globally redirect macOS `/tmp`. If the RAM volume is absent or too small, use
system `/tmp` only as a documented exception and report it in the handoff.

## Change procedure

Use an isolated worktree, pressure-test in a temporary environment, run the relevant
quality/release/anti-pattern gates, open a focused PR, and merge only after hosted
checks and artifact identity checks pass. Never treat a green job that did not execute
as a passing gate.
