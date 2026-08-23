# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# QuReddy repository guidance for Claude Code and other coding agents.

## Contents

1. [Instruction hierarchy](#instruction-hierarchy)
2. [Deliberate QuReddy divergences](#deliberate-qureddy-divergences)
3. [Change procedure](#change-procedure)

## Instruction hierarchy

Read and apply these sources in order:

1. **`~/claude/CLAUDE.md` (platform guidance).** This is the BQP-wide contract for
   licensing, canonical repositories, Python/OpenSSL baselines, worktree and PR
   procedure, and cross-repository architecture. It is auto-loaded because Claude
   Code walks up from the working directory. Platform policy remains authoritative
   for cross-repo and safety rules; record any deliberate repo exception below.
2. **This file (QuReddy guidance).** These are rules specific to this repository.
   They refine, but do not silently weaken, the platform contract.
3. **Task-scoped skills under `.claude/skills/` and the installed BreachSAFE skill
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
- **Distribution:** releases currently publish to TestPyPI only. Production PyPI is
  intentionally not probed or published until separately authorized; a production
  PyPI 404 is expected, not a release failure.
- **Runtime baseline:** Python commands use 3.12+ (3.14 in current CI), and native
  OpenSSL validation uses the pinned 3.5.7 LTS contract.
- **SSH scope:** the SSH acquisition redesign and `ssh-audit` work remain parked in
  the 0.5.0 backlog unless a maintainer explicitly changes that scope.

## Change procedure

Use an isolated worktree, pressure-test in a temporary environment, run the relevant
quality/release/anti-pattern gates, open a focused PR, and merge only after hosted
checks and artifact identity checks pass. Never treat a green job that did not execute
as a passing gate.
