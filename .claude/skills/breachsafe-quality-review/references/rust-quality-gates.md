# Rust quality gates (Mode 1 — fast local check)

Applies to the Rust components (QuCrypt / `breachsafe-crypto-rs`, QuCert /
`breachsafe-pki-rs`, and QuCustody once crate code exists). Run this before opening a PR,
or whenever you want to confirm a change compiles and the suite is green.

## Environment first

Check the repo's own `CLAUDE.md` / `README` for platform-specific env vars before running
anything. At least one BQP Rust repo requires `OPENSSL_DIR` to be set for every `cargo`
invocation that compiles, because the platform's Homebrew OpenSSL isn't picked up by
default — the exact path is a local machine detail, not something to hardcode here. If a
build fails with an OpenSSL-not-found error, that's the first thing to check.

## Sequence

Run in order. Stop and surface the first failing step rather than pushing past it — a
later step's failure is often just noise once an earlier one is red.

1. **Format check (non-mutating)**
   ```bash
   cargo fmt --check
   ```
   Never run bare `cargo fmt` to "fix" this in an audit context — formatting is a
   separate, deliberate commit, not something a review silently applies.

2. **Build**
   ```bash
   cargo build
   ```

3. **Full test suite** — must be fully green. Any failure is a regression, not an
   accepted baseline to work around.
   ```bash
   cargo test
   ```

4. **Doc tests** — inline doc-comment examples must compile and pass.
   ```bash
   cargo test --doc
   ```

5. **Lint**
   ```bash
   cargo clippy --all-targets
   ```
   Treat `-D warnings` (deny warnings) as the target bar for library code if the repo's
   CI does; check the repo's own gate configuration rather than assuming.

6. **Supply-chain / release gates** — `cargo audit`, `cargo deny`, crates.io publish
   checks are **not** this skill's job. If you want those, use `breachsafe-release`.

## Recording a baseline

Before starting a change, capture the current pass/fail count (`cargo test --quiet 2>&1 |
tail -3`) so you have something concrete to compare against when you re-run after your
change. Don't trust "still passes" from memory — re-run and compare the actual counts.

## Report format

One line per step:

```
1. cargo fmt --check     : PASS / FAIL
2. cargo build            : PASS / FAIL
3. cargo test              : PASS / FAIL (N passed, M failed)
4. cargo test --doc        : PASS / FAIL
5. cargo clippy            : PASS / FAIL (N warnings)

VERDICT: GREEN / BLOCKED — <reason>
```

If everything passes and the change touches cryptographic or security-relevant code,
say so explicitly and point at `breachsafe-security-audit` and `breachsafe-conformance`
for the checks this skill does not do — this skill confirms the code builds and the
existing tests pass, not that the crypto is correct or standards-conformant.
