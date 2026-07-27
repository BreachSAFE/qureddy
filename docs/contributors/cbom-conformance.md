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
   references, and secret-like prohibited material.

`rfc3339-validator` is an explicit development dependency. The conformance check first
proves that malformed `date-time` values are rejected; missing format support
therefore fails closed instead of silently weakening schema validation.

## Controlled upgrade procedure

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
