# Pinned CycloneDX 1.7.1 JSON schemas

These four files are the minimum offline set referenced by the official
`bom-1.7.schema.json`. They are copied byte-for-byte from CycloneDX
specification tag `1.7.1`, commit
`b29bae660048e0ad2fbc5f2972927b442ce951c4`, under the upstream Apache-2.0
license.

The authoritative source URLs and SHA-256 digests are in
`tests/conformance/manifest.json`. The gate computes every digest before
constructing the validator and does not fetch schemas from the network.
