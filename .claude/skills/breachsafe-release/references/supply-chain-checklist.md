# Supply-chain checklist

Audit only. This checks whether the dependency tree is scanned for known vulnerabilities,
license problems, and provenance gaps, and — more importantly — whether that scan is wired
so a finding actually **fails the build**. A tool that runs but exits 0 on findings enforces
nothing.

Run the section matching the ecosystem(s) detected (`Cargo.toml` / `pyproject.toml`). See
`SKILL.md` for the dispatch check and the authorization gate.

---

## Rust (cargo audit + deny + vet + CI enforcement)

### Setup

```bash
cd <crate root>
# Validate tools are installed — do not assume they are:
cargo audit --version || echo "MISSING: cargo install cargo-audit"
cargo deny  --version || echo "MISSING: cargo install cargo-deny"
cargo vet   --version || echo "MISSING: cargo install cargo-vet"
```

### Step 1 — cargo audit (RustSec advisory DB)

```bash
# Lockfile must exist and be committed, or version matching is unreliable:
test -f Cargo.lock && git ls-files --error-unmatch Cargo.lock >/dev/null 2>&1 \
  && echo "Cargo.lock committed: OK" || echo "FINDING: Cargo.lock missing or untracked"

cargo audit 2>&1 | tail -20
# In CI this MUST use --deny warnings, or a finding still exits 0:
cargo audit --deny warnings; echo "exit=$?"   # exit!=0 means it would fail CI (good)
```

- [ ] `Cargo.lock` present AND committed
- [ ] `cargo audit` clean (no RUSTSEC advisories on the resolved tree)
- [ ] CI invokes `cargo audit --deny warnings` (not bare `cargo audit`) — otherwise
      findings pass CI silently

### Step 2 — cargo deny (licenses, sources, bans, advisories)

```bash
# The config MUST be named exactly deny.toml (or .cargo/deny.toml). A misnamed file
# silently falls back to cargo-deny's default config — a real historical bug in this
# codebase family; verify current state, don't assume either the bug or the fix:
ls deny.toml .cargo/deny.toml 2>/dev/null || echo "FINDING: no deny.toml (check for a typo'd filename)"
find . -maxdepth 2 -iname '*deny*toml' -not -path './target/*'

cargo deny check 2>&1 | tail -30; echo "exit=$?"
# A "falling back to default config" message = the config isn't loading.
# A "failed to deserialize" error = obsolete schema (check [advisories]/[bans] shape
# against the installed cargo-deny version's current docs).
```

- [ ] Config file named exactly `deny.toml` (not a typo'd variant)
- [ ] `cargo deny check` loads the config (no "falling back to default")
- [ ] Config parses under the installed cargo-deny's current schema
- [ ] License allow-list matches the crate's actual dependency licenses
- [ ] CI invokes `cargo deny check` and the step can fail the build

### Step 3 — cargo vet (dependency provenance / review)

```bash
test -d supply-chain && echo "cargo-vet initialized" || echo "NOTE: cargo vet not set up"
cargo vet --locked 2>&1 | tail -20; echo "exit=$?"
# This step only AUDITS whether cargo-vet exists and passes — it does not run
# `cargo vet init` or record new exemptions; that's a maintainer decision.
```

- [ ] `supply-chain/` (cargo-vet store) exists for a crate aiming at high assurance
      (government/finance/infrastructure-grade, or any PQC/crypto-primitive crate)
- [ ] `cargo vet` passes (all deps audited or exempted with rationale)
- [ ] Note: if cargo-vet is absent because CI itself doesn't exist yet, don't treat the
      missing cargo-vet as the critical finding — sequence it behind "no CI at all," since
      vet without CI to run it is the same enforcement gap either way.

### Step 4 — CI enforcement (the gate that makes the above non-optional)

```bash
ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null || echo "FINDING: no CI workflows"

grep -rn 'cargo audit\|cargo deny\|cargo vet\|fmt\|clippy\|--deny\|fail-under' \
  .github/workflows/ 2>/dev/null || echo "CI present but no supply-chain/quality gates found"

# Local-only enforcement doesn't count for shared safety:
grep -rln 'cargo audit\|cargo deny' scripts/hooks/ .git/hooks/ 2>/dev/null \
  && echo "NOTE: gate found in a local hook only — skippable, not enforced for all contributors"
```

Recommended minimum CI gate order (for a findings report, not to implement here):
`cargo fmt --check` → `cargo clippy --all-targets -- -D warnings` → `cargo test`
(matrix over supported toolchains) → `cargo audit --deny warnings` → `cargo deny check` →
optional coverage gate → `cargo vet`.

- [ ] CI exists (`.github/workflows/`)
- [ ] Gates run in CI, not just a local hook
- [ ] Each gate can actually FAIL the build (`-D warnings`, `--deny warnings`, non-zero exit)
- [ ] Toolchain matrix matches the crate's declared MSRV (`rust-version` in `Cargo.toml`)

---

## Python (pip-audit + deptry + reuse lint + gitleaks + CI enforcement)

The Python-ecosystem components in this family (QuReddy, Qurum) use `pip-audit` for
vulnerability scanning, `deptry` for unused/missing-dependency detection, `reuse lint` for
SPDX license-header compliance, and `gitleaks` (or `trufflehog`) for secret scanning — the
direct equivalents of the Rust `audit`/`deny`(-partial)/vet stack. Same trap applies: a tool
that runs but doesn't gate the merge enforces nothing.

### Setup

```bash
cd <package root>
pip-audit --version 2>/dev/null || echo "MISSING: pip install pip-audit"
deptry --version    2>/dev/null || echo "MISSING: pip install deptry"
reuse --version      2>/dev/null || echo "MISSING: pip install reuse"
gitleaks version     2>/dev/null || echo "MISSING: install gitleaks (or use trufflehog)"
```

### Step 1 — pip-audit (dependency CVEs)

```bash
test -f pyproject.toml && echo "pyproject.toml present" || echo "FINDING: no pyproject.toml"
pip-audit 2>&1 | tail -30; echo "exit=$?"
```

- [ ] `pip-audit` clean, or any findings are explicitly HIGH/CRITICAL-gated in CI (a known
      LOW/MEDIUM upstream CVE with no fix available is a legitimate accepted-risk case;
      an unreviewed HIGH/CRITICAL is not)
- [ ] A lockfile (`uv.lock`, `poetry.lock`, or equivalent) is committed so the resolved tree
      is reproducible

### Step 2 — deptry (unused / missing / transitive-misuse dependencies)

```bash
deptry . 2>&1 | tail -30; echo "exit=$?"
```

- [ ] No unused declared dependencies (dead weight in the supply-chain surface)
- [ ] No missing dependencies (imported but not declared — works today, breaks on a clean
      install elsewhere)
- [ ] No transitive dependency used as if it were direct

### Step 3 — reuse lint (SPDX / license-header compliance)

```bash
reuse lint 2>&1 | tail -30; echo "exit=$?"
```

- [ ] `reuse lint` passes — every source file has a valid `SPDX-License-Identifier` header
      (or is covered by `REUSE.toml`/`.reuse/dep5` for files that can't carry a header)
- [ ] The declared license matches the `license` field in `pyproject.toml` and the LICENSE
      file(s) actually present at repo root

### Step 4 — Secret scanning

```bash
gitleaks detect --no-git -v 2>&1 | tail -30; echo "exit=$?"
# Or, scanning history rather than just the working tree:
gitleaks detect -v 2>&1 | tail -30
```

- [ ] Clean secret scan on the current tree
- [ ] CI runs this on the diff (or full history periodically) — a clean local run today
      doesn't prove it's enforced

### Step 5 — CI tiering and enforcement

Per-PR vs. per-release tiering is a legitimate cost/noise tradeoff at small dependency-tree
scale — but only if it's a deliberate, documented split, not an accidental gap. Verify which
tier each gate is actually in, and that HIGH/CRITICAL findings do gate something real:

```bash
ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null || echo "FINDING: no CI workflows"
grep -rn 'pip-audit\|deptry\|reuse\|gitleaks\|trufflehog\|bandit' \
  .github/workflows/ 2>/dev/null || echo "CI present but no supply-chain gates found"
```

- [ ] Each gate above runs in CI (per-PR, per-release, or both — state which)
- [ ] HIGH/CRITICAL `pip-audit` findings can actually block (a merge gate or a release gate,
      not just a report artifact nobody reads)
- [ ] If gates are split per-PR (cheap/fast: lint, format, unit tests, secret scan) vs.
      per-release (heavier: full `pip-audit`, license sweep, build verification), that split
      is documented somewhere a contributor would find it — an undocumented split reads the
      same as an accidental gap from the outside

---

## Cross-ecosystem honesty rules

- Report exit codes, not descriptions. "Ran clean" without the exit code isn't verified.
- A finding that's only enforced in a local hook (pre-commit, `.git/hooks/`) is not
  enforced — anyone can skip a local hook; treat it as equivalent to "not enforced in CI."
- When both a Rust and Python surface exist in the same repo (e.g. a Rust core with a Python
  binding crate), audit both independently and say which ecosystem each finding belongs to.
