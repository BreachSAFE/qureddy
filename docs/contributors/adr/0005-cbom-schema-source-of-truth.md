# ADR 0005 — Consume CycloneDX 1.6 CBOM schema verbatim, promote the prototype to MVP 0.2/0.3

**Status:** Accepted
**Date:** 2026-07-23
**Deciders:** Paul Volosen (project lead)
**Consulted:** Claude (implementation, this ADR), Codex (architect role per `CLAUDE.md` Governance — schema-fidelity review pending on the follow-up scope in `## Not yet done`)
**Informed:** BreachSAFE co-founder
**Supersedes:** none
**Superseded by:** none

---

## Context

Issue #61 required this decision before any CBOM code landed: emit CycloneDX verbatim
(the IBM/CBOM-defined `cryptoProperties` profile that the CBOMkit ecosystem emits) or
fork a QuReddy-specific dialect. Forking was rejected in #61's own analysis — schema
drift is a one-way, breaking-change trap (same shape as #59's testssl.sh alignment
problem), and it optically positions QuReddy as competing with the spec instead of
consuming it.

Ahead of this ADR being written, a rapid-prototype implementation already existed on the
`prowler-rapid-prototype` branch (`src/qureddy/output/cbom.py`, `src/qureddy/scanners/tls/cert_probe.py`),
explicitly marked in both files' module docstrings as "NOT the tracked MVP implementation
... requires an ADR before code" per #61's own gate. That prototype:

- Uses `cyclonedx-python-lib` (declared as a real dependency as of this session — it was
  previously an undeclared transitive dependency of `pip-audit`, a latent install bug,
  fixed separately from this ADR)
- Emits native CycloneDX 1.6 `CryptoProperties`/`CertificateProperties`/`ProtocolProperties`
  via the library's own model classes — not hand-rolled serialization
- Has one documented, narrow deviation from pure library usage (see `## Provides-edge
  gap` below)
- Was verified working end-to-end against real targets and against Qurum's actual
  consumer code, not just unit tests

This ADR's job is to decide whether that already-working design is the right one to lock
in and promote, or whether it needs to change first. It also updates the file-level
"not the tracked MVP" disclaimers once accepted.

## Decision

**Emit CycloneDX 1.6 verbatim via `cyclonedx-python-lib`'s native model classes. Do not
hand-roll BOM serialization. Extend only through CycloneDX's own extension point
(`properties[]`), never via invented top-level fields.**

Concretely:

1. **Schema source of truth:** the official CycloneDX 1.6 JSON Schema
   (`https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json`),
   not a QuReddy-authored copy. `cyclonedx-python-lib` 11.11.0's `JsonV1Dot6` serializer is
   the implementation of that schema QuReddy delegates to.
2. **Cryptographic assets** (negotiated groups, protocol versions, certificates) render as
   `Component(type=CRYPTOGRAPHIC_ASSET, crypto_properties=...)`, using the library's
   `CryptoProperties`/`ProtocolProperties`/`CertificateProperties` classes — the same
   `cryptoProperties` shape the IBM/CBOM-originated profile and the broader CBOMkit
   ecosystem emit, inherited for free by using the library rather than a fork.
3. **QuReddy-specific facts with no native CycloneDX field** (today: `qureddy:scan.status`,
   `qureddy:scan.failure_category`, `qureddy:certificate.serial`) go in
   `bom.metadata.properties` / `Component.properties` — CycloneDX's own documented
   extension mechanism — never as invented root-level fields (the root schema sets
   `additionalProperties: false`).
4. **The one accepted deviation** from pure library usage: `provides` dependency edges
   are patched into the serialized JSON post-hoc, because `cyclonedx-python-lib`'s
   `Bom.register_dependency` exposes `depends_on` but has no `provides` parameter
   (confirmed via `inspect.signature(Dependency.__init__)`) despite `provides` being
   valid CycloneDX 1.6. This is marked `ANTIPATTERN ACCEPTED: raw-json-post-processing`
   in `cbom.py`'s module docstring — narrow, documented, and independently schema-validated
   (see `## Evidence` below), not a silent hack.
5. **Promote `cbom.py`/`cert_probe.py` off prototype status.** They become the real MVP
   0.3 (CBOM) and MVP 0.2 (certificate) implementations. The "NOT the tracked MVP
   implementation" disclaimers in both files' module docstrings are removed in the same
   change that lands this ADR.

## Evidence

Real, independently verified — not asserted:

- **Schema validation.** A CBOM generated against `breachsafe.ai` (successful scan,
  hybrid PQC negotiated) and one against `localhost:43000` (hard-failed scan, no
  listener) were both validated against the official CycloneDX 1.6 JSON Schema using
  `jsonschema.Draft7Validator` with `FormatChecker()` enabled (catches RFC 3339
  datetime format errors, not just structural shape). **Zero violations on both.** This
  includes the raw-JSON `provides` patch — the one place this codebase deviates from
  pure library serialization is exactly the place independently confirmed still
  schema-valid.
- **Cross-repo consumption.** The same CBOM shape was piped through Qurum's actual
  parser (`qurum cbom <file> --knowledge`, not a mock) and correctly resolved
  `crypto_library_name`/`crypto_library_version` for every asset via the
  `dependsOn`/`provides` graph — confirmed live earlier in the `prowler-rapid-prototype`
  work, not merely unit-tested in isolation.
- **Verified commit:** `52dd2dd` on `prowler-rapid-prototype`.

## Consequences

**What this unlocks:**
- `cbom.py`/`cert_probe.py` can merge to `main` as real MVP 0.2/0.3 work instead of
  staying indefinitely on a prototype branch.
- Issue #197 (discovery/lifecycle/tool/formulation metadata) becomes well-scoped
  follow-up work built on an accepted foundation, not a design debate on top of
  unaccepted prototype code.

**What this does not resolve (see `## Not yet done`):** several of #61's original
acceptance criteria are process/tooling items, not design decisions, and remain open.

## Not yet done

Issue #61 listed acceptance criteria beyond "pick a schema and prove it validates."
This ADR locks the decision; these are follow-up implementation work, tracked
separately so they don't block the decision itself:

- [ ] CI gate: every emitted CBOM validated against a **vendored** copy of the official
      schema (this ADR's validation was done manually, ad hoc — needs to run on every
      PR, not just once here)
- [ ] `tests/fixtures/cbom/` vendored schema fixture + a `pytest` test that fails the
      build on schema drift
- [ ] Walk `mvp-implement/SKILL.md`'s locked Pydantic fields and cite each one's
      CycloneDX/IBM-CBOM equivalent (the `ANTIPATTERN ACCEPTED: speculative generality`
      markers on `Asset`/`Finding` predate this ADR and need the cross-reference #61
      asked for)
- [ ] `docs/reference/json-schema.md` cross-references CycloneDX 1.6 alongside
      `qureddy.scan.v1`
- [ ] Issue #197's scope (lifecycle phase, tool component, formulation `timeStart`/
      `timeEnd`) — a real, well-specified extension of this baseline, deliberately left
      out of this ADR to keep this decision narrow and reviewable

## Alternatives considered

### Fork a QuReddy-specific CBOM dialect

Rejected per #61's own analysis: ecosystem-hostile, forces every downstream consumer
(Qurum included) to write a QuReddy-specific adapter, and schema drift after publishing
is a one-way breaking change. The evidence in this ADR (zero violations against the real
upstream schema) confirms the verbatim approach was achievable without loss of the data
QuReddy actually needed to express (`properties[]` covered every QuReddy-specific fact
that came up).

### Hand-roll BOM serialization instead of depending on `cyclonedx-python-lib`

Rejected — reintroduces exactly the schema-drift risk a schema library exists to
prevent, for a library that already correctly serializes the 1.6 shape (confirmed by
this ADR's validation). The one gap in the library's Python API (`provides` edges) is
narrow enough to patch post-hoc without hand-rolling the rest.

### Wait for CycloneDX 1.7 or a full IBM/CBOM commit pin before deciding

Rejected — same reasoning as #61 itself gave for not waiting on other pending specs
(#57/#58): 1.6 is stable, already what the CBOMkit ecosystem emits today, and waiting
means shipping obsolete. If 1.7 or a more specific IBM/CBOM profile pin becomes load-bearing
later, that's a superseding ADR, not a reason to block this one.

## Related

- Issue #61 — the acceptance criteria this ADR resolves the design-decision portion of
- Issue #197 — the follow-up discovery/lifecycle/formulation metadata scope, deliberately
  out of scope here
- Issue #195, #190 — CBOM correctness/completeness fixes landed on the same prototype
  branch before this ADR, both using the `properties[]` extension pattern this ADR locks
  in as the correct mechanism
- Issue #196 — cross-repo coupling to Qurum's private `_linked_libraries` shape; not
  resolved by this ADR, tracked separately
- [ADR 0004 — Multi-scanner architecture](0004-multi-scanner-architecture.md)
