<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR 0004 — Multi-scanner architecture for MVP 0.2

**Status:** Proposed
**Date:** 2026-04-27
**Deciders:** Paul Volosen, project lead
**Consulted:** Claude (drafting), Codex (architect / arbiter)
**Informed:** future MVP 0.2 contributors
**Supersedes:** none
**Superseded by:** none
**Tracking issue:** [#39](https://github.com/paul007ex/qureddy/issues/39)

---

## Context

QuReddy's MVP 0.1 ships a single TLS scanner. The roadmap (per `CLAUDE.md`) commits to five additional scanners by MVP 0.6 (cert at 0.2, CBOM at 0.3, SSH at 0.4, config at 0.5, source-code at 0.6) and to a CycloneDX CBOM emission step at MVP 0.3.

The current architecture has implicit single-scanner assumptions throughout:

- `cli.py:scan_tls` constructs `TLSScanner` directly. There is no `Scanner(Protocol)` abstraction.
- `scanners/tls/scanner.py` runs hybrid + classical probes inline; there is no abstract `Probe` concept.
- `MVP_POLICY` is a top-level tuple constant in `core/policy.py`, not a per-scanner registry.
- `RetryConfig` lives in `scanners/tls/scanner.py`, not in a generic retry layer.
- `FailureCategory` enum is flat (`LOCAL_OPENSSL_*`, `TLS_HANDSHAKE_FAILED`, `PARSE_NO_GROUP`, etc.). Each scanner contributing categories will produce N×M growth by MVP 0.6.
- The `CycloneDX-flavored` fields on `Asset` and `Finding` (`bom_ref`, `oid`, `nist_quantum_security_level`, `algorithm`, `primitive`, `parameter_set_identifier`, `key_size`) are present but unpopulated. Their presence is accepted via the `ANTIPATTERN ACCEPTED: speculative generality, because CycloneDX field names will land at MVP 0.3 and JSON schema stability matters for early adopters` marker in `core/models.py`.

These are not bugs. They are correct for MVP 0.1 — premature abstraction at single-scanner stage is itself an antipattern. But every one of them must be lifted before MVP 0.2's certificate scanner can land cleanly. Three options exist for when:

1. **Refactor pre-0.2 in a dedicated PR.** Tempting, but the abstractions are speculative until a second concrete scanner exists. They tend to be wrong.
2. **Refactor as part of MVP 0.2's first PR.** The cert scanner forces the correct shape.
3. **Copy-paste-fork per scanner.** Scales to 2; breaks at 5. By MVP 0.6 this is the worst-of-both-worlds maintenance burden.

This ADR adopts option 2 and locks the shape of the refactor, so MVP 0.2's first PR doesn't get bogged down in design discussion at PR-review time.

## Decision

Adopt the following five changes as part of MVP 0.2's first PR (the cert scanner introduction).

### 1. `Scanner(Protocol)` interface in `core/`

A new file `src/qureddy/core/scanner.py` defines:

```python
from typing import Protocol
from qureddy.core.models import ScanResult, ScanTarget


class Scanner(Protocol):
    """Common interface every QuReddy scanner implements."""

    name: str  # "tls", "cert", "cbom", ...

    def scan(
        self,
        target: ScanTarget,
        *,
        timeout_seconds: int,
    ) -> ScanResult: ...
```

`TLSScanner` already matches this shape; the change is just declaring it as a `Protocol` and importing from there. The CLI dispatches by `scanner.name`; subcommand wiring stops being scanner-specific.

### 2. `RetryConfig` migrates to `core/retry.py`

The `RetryConfig` dataclass currently in `scanners/tls/scanner.py` is generic — it has nothing TLS-specific. Move it next to `run_with_retries`. Every scanner takes a `RetryConfig` constructor argument.

### 3. Per-scanner policy modules

`MVP_POLICY` becomes `TLS_POLICY` (lives in `scanners/tls/policy.py` or stays in `core/policy.py` namespaced). MVP 0.2 introduces `CERT_POLICY` for the certificate scanner. The `classify_evidence` function takes the policy as an argument:

```python
def classify_evidence(
    asset: Asset,
    evidence: list[Evidence],
    policy: tuple[PolicyRule, ...],
) -> list[Finding]: ...
```

### 4. Failure-category namespacing

The flat `FailureCategory` enum is replaced with namespaced values to prevent N×M bloat by MVP 0.6.

| Current (MVP 0.1) | Proposed (MVP 0.2+) |
|---|---|
| `LOCAL_OPENSSL_MISSING` | `local_openssl_missing` |
| `LOCAL_OPENSSL_BROKEN` | `local_openssl_broken` |
| `LOCAL_OPENSSL_VERSION_UNREADABLE` | `local_openssl_version_unreadable` |
| `LOCAL_OPENSSL_TOO_OLD` | `local_openssl_too_old` |
| `LOCAL_OPENSSL_LACKS_GROUP` | `local_openssl_lacks_group` |
| `TARGET_CONNECT_FAILED` | `tls.target_connect_failed` |
| `TLS_HANDSHAKE_FAILED` | `tls.handshake_failed` |
| `SNI_REQUIRED_OR_WRONG` | `tls.sni_required_or_wrong` |
| `MIDDLEBOX_OR_MTU_FAILURE` | `tls.middlebox_or_mtu_failure` |
| `PARSE_NO_GROUP` | `tls.parse.no_group` |
| `PARSE_AMBIGUOUS` | `tls.parse.ambiguous` |
| `UNEXPECTED_GROUP` | `tls.parse.unexpected_group` |

Local-capability failures stay un-namespaced because they apply to any scanner that depends on a local binary. Probe and parser failures are scanner-namespaced. Per-scanner subsets become filterable (`category.startswith("tls.")`). The `--retry-on` allowlist becomes per-scanner.

This is the most invasive change of the five. It is **schema-breaking** for the JSON output's `summary.failure_category` field. Schema version bumps from `qureddy.scan.v1` to `qureddy.scan.v2`. Existing JSON consumers must migrate. Worth doing once at MVP 0.2 (where consumers are minimal) rather than later when the surface is larger.

### 5. CycloneDX field strategy

The `bom_ref`, `oid`, `nist_quantum_security_level`, `algorithm`, `primitive`, `parameter_set_identifier`, `key_size` fields on `Asset` and `Finding` are currently `Optional` and unpopulated.

**Decision: populate, do not remove.** MVP 0.3 (CBOM emission) is one milestone away; the CBOM emitter needs the data the moment it ships. At MVP 0.2:

- `TLSScanner` populates `algorithm = "X25519MLKEM768"`, `primitive = "kyber"`, `parameter_set_identifier = "ML-KEM-768"`, `nist_quantum_security_level = 3`, `bom_ref = "asset-{id}"` for hybrid findings. Classical findings get `algorithm = "X25519"`, `primitive = "ecdh"`, `nist_quantum_security_level = 0`.
- `CertScanner` populates the same set for certificate-derived findings (signature algorithms, key sizes, OIDs).
- The `ANTIPATTERN ACCEPTED` marker in `core/models.py` is removed.

## Consequences

**Adopted:**

- MVP 0.2's first PR is larger than a minimal "add a cert scanner" change. It carries the refactoring weight.
- JSON schema version bumps to `qureddy.scan.v2` once at MVP 0.2. All subsequent scanner additions stay on v2 until v1.0.
- Every scanner can be unit-tested in isolation through the `Scanner` protocol.
- Adding scanner #N becomes ~1 file change in the right place, instead of touching 6 places.
- `CHANGELOG.md` gains a `Breaking Changes` section at MVP 0.2 documenting v1 → v2 migration.
- `docs/reference/json-schema.md` documents both v1 and v2 with a migration table.
- The `ANTIPATTERN ACCEPTED` marker for CycloneDX speculative-generality is retired.

**Rejected (alternatives considered):**

- **Refactor pre-0.2 in a dedicated PR.** Speculative abstractions tend to be wrong. Wait for the second concrete scanner.
- **Copy-paste-fork per scanner.** Scales to 2, breaks at 5. By MVP 0.6 it is unmaintainable.
- **Plugin system / entry points.** Premature for an OSS scanner with hardcoded scope. Reconsider at v1.0 when third-party scanner contributions might be a thing.
- **Hold schema bump until MVP 0.3 (CBOM).** Tempting because CBOM emission is itself a schema event, but bundling two schema-breaking changes at the same milestone increases the test/doc churn. Bumping at 0.2 (small consumer base) and again at 1.0 (lock for PyPI) is cleaner than 0.2 + 0.3 + 1.0.

## Adoption checklist

The implementing PR (MVP 0.2's first) closes [issue #39](https://github.com/paul007ex/qureddy/issues/39) when it merges and updates this ADR's status from `Proposed` to `Accepted`.

The PR must:

- [ ] Promote this ADR's `Status:` from `Proposed` to `Accepted` and add the implementing PR number under `Superseded by:` (which stays `none`; this ADR is implemented, not superseded)
- [ ] Define `core/scanner.py` with the `Scanner` protocol
- [ ] Migrate `RetryConfig` from `scanners/tls/scanner.py` to `core/retry.py`
- [ ] Restructure `MVP_POLICY` into per-scanner policies; update `classify_evidence` signature
- [ ] Bump JSON schema to `qureddy.scan.v2`; namespace `FailureCategory`; update `--retry-on` parsing; document v1→v2 in `docs/reference/json-schema.md`
- [ ] Populate CycloneDX fields per the strategy above; remove the `ANTIPATTERN ACCEPTED` marker
- [ ] Update `docs/explanation/architecture.md` diagrams to reflect the new shape
- [ ] Add `CHANGELOG.md` `Breaking Changes` entry
- [ ] Update `docs/reference/failure-categories.md` and `docs/reference/json-schema.md` for the new namespacing

## Open questions for the implementing PR

These were left open by the ADR author and discussion in [issue #39](https://github.com/paul007ex/qureddy/issues/39):

1. **Scanner protocol shape:** is `Scanner(Protocol)` enough, or do we need a richer base class with default `scan_id` generation, retry wiring, etc.?
2. **Failure-category string format:** dotted (`tls.handshake_failed`) is proposed. Slash (`tls/handshake_failed`) is the alternative. Either works; lock one before code lands.
3. **`--retry-on` syntax with namespacing:** does `--retry-on tls.parse.no_group` work, or do we need a wildcard like `--retry-on tls.parse.*`? The latter is more powerful but a bigger CLI surface.

## References

- [`CLAUDE.md`](../../../CLAUDE.md) — Roadmap (MVP 0.1 → 0.6 → 1.0)
- [`docs/explanation/architecture.md`](../../explanation/architecture.md) — current architecture (single-scanner)
- [`docs/contributors/coding-rules.md`](../coding-rules.md) §1 — minimum viable abstraction
- [`.claude/skills/mvp-implement/SKILL.md`](../../../.claude/skills/mvp-implement/SKILL.md) — operational authority for the current milestone
- [ADR 0002](0002-diataxis-documentation-standard.md) — template followed by this ADR
- [Issue #39](https://github.com/paul007ex/qureddy/issues/39) — the GitHub-side tracking artifact for this ADR
