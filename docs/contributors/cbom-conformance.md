# CycloneDX conformance gate

QuReddy validates the final JSON bytes emitted by an installed `qureddy`
console command. The gate is deliberately downstream of
`cyclonedx-python-lib` serialization and QuReddy's narrow final-byte patches.

The same bytes must pass three independent layers:

1. the official CycloneDX 1.7.1 JSON schemas, vendored at an exact
   specification commit and checked by SHA-256;
2. CycloneDX CLI 0.33.1, downloaded from its exact release asset and checked
   by SHA-256 before execution;
3. BreachSAFE semantic checks for exact `specVersion`, duplicate and dangling
   references (including annotation `bom-ref` uniqueness and every annotation
   `subjects` entry resolving to a component), and secret-like prohibited material.

`rfc3339-validator` is an explicit development dependency. The conformance check first
proves that malformed `date-time` values are rejected; missing format support
therefore fails closed instead of silently weakening schema validation.

## Contents

1. [Controlled upgrade procedure](#1-controlled-upgrade-procedure)

## 1. Controlled upgrade procedure

Schema or validator upgrades must be isolated in one pull request:

1. Resolve the upstream tag to its full commit and review the upstream diff.
2. Copy only the schemas recursively required by the root BOM schema.
3. Record source URLs and recompute every schema SHA-256 in
   `tests/conformance/manifest.json`.
4. Pin the independent CLI release, URLs, and publisher-provided digests in
   `tests/conformance/cyclonedx-cli-*.json`.
5. Regenerate positive fixtures from an installed candidate artifact. Preserve
   provenance classification and never relabel synthetic data as captured.
6. Regenerate synthetic-negative fixtures from a schema-valid positive base.
7. Review every expected result in the schema/CLI/semantic detection matrix.
8. Run the complete CI gate from a clean checkout. Any unexpected pass,
   unexpected rejection, digest drift, or nondeterministic final output blocks
   the upgrade.

Do not update a schema file, checksum, fixture, and expected outcome merely to
make a failing gate green. Each changed byte needs an upstream or captured
provenance explanation in the pull request.

## 2. Downstream consumer contract (drift gate)

QuReddy's CBOM has live downstream consumers that read a specific, stable surface:

- **breachsafe-ux** (the wizard's `tools/qureddy/qureddy.yaml`) renders the readiness
  posture banner from `qureddy:scan.readiness`, the `qureddy:scan.status` highlight, and a
  CBOM schema-validity badge.
- **breachsafe-mint-oscal** (`adapters/cbom.py`) derives the OSCAL POA&M readiness from the
  native `cryptoProperties` layer and raises if a crypto component has a null `assetType`.

A CBOM reshape (for example the 0.2.23 move to native annotations/occurrences, #287) is
only safe because those consumers read that stable surface, not the layer being reshaped.
To keep it that way, `tests/fixtures/cbom_consumer_contract.yaml` records what each
consumer depends on and `tests/test_cbom_consumer_contract.py` fails — naming the consumer
— if a rendered CBOM ever stops providing it. Removing a requirement means updating that
consumer in lockstep and editing the fixture deliberately; the gate exists so it can never
happen by accident.
