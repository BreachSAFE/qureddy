# ADR 0007 — Emit CycloneDX 1.7 from captured observations

**Status:** Accepted
**Date:** 2026-07-26
**Deciders:** Paul Volosen (project lead)
**Supersedes:** ADR 0005's producer-version and attribution decisions only

## Context

ADR 0005 correctly chose the official CycloneDX model rather than a QuReddy dialect,
but fixed the producer to 1.6 and represented local OpenSSL as a library used by the
remote endpoint. Research for issue #31 demonstrated three corrections:

- `cyclonedx-python-lib` 11.11.0's `JsonV1Dot7` output validates as CycloneDX 1.7.
- Adding one endpoint object to both `metadata.component` and `components` makes the
  library's discriminator replace its `bom-ref` on each render.
- OpenSSL is a local collection tool. It is not evidence that the remote endpoint
  depends on OpenSSL, especially when capability detection failed.

The official schema evidence is CycloneDX specification tag `1.7.1`, commit
`b29bae660048e0ad2fbc5f2972927b442ce951c4`. The pinned files and SHA-256 digests are:

- `bom-1.7.schema.json`: `73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce`
- `cryptography-defs.schema.json`: `027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44`
- `jsf-0.82.schema.json`: `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae`
- `spdx.schema.json`: `ea6e844ee6fba1e93473d94834d0ee0996970533497935f932f73d488ffdf4a3`

Independent validation used `cyclonedx-cli` 0.33.1; the tested macOS arm64 binary's
SHA-256 is `750c148780154833f6401f9067d08c5a4c31567b6ee3c26c062c3a95c62d741c`.

## Decision

QuReddy emits CycloneDX 1.7 with these invariants:

1. The endpoint is the stable `metadata.component` root with `bom-ref="endpoint"`.
   It is not duplicated in `components`.
2. QuReddy and the locally selected OpenSSL executable are
   `metadata.tools.components`. Neither is a remote-endpoint dependency.
3. Cryptographic inventory is derived only from positive typed observations:
   `negotiated`, `offered`, or `observed`. Findings and negative, inferred, unknown,
   or not-testable outcomes cannot create assets.
4. The endpoint `provides` the cryptographic assets that those observations support.
5. Certificate data comes from the certificate observation captured during the scan.
   A renderer must not fetch the target again.
6. The library serializer owns the document. Final-byte post-processing is restricted
   to `dependencies[].provides` and the native 1.7 certificate `serialNumber`, which
   `cyclonedx-python-lib` 11.11.0 cannot model.
7. Final bytes receive semantic checks for exact spec version, unique and resolvable
   graph references, and private-key material before they reach stdout.

## Consequences

Stable references make normalized renders byte-repeatable. Sparse and failed scans stay
valid but do not fabricate inventory. Output describes target observations separately
from collection provenance.

The 1.7 serializer does not remove the need for independent conformance. Issue #32 owns
the pinned schema/CLI harness and its positive and negative fixture matrix. Dependency
range changes must be accompanied by the installed-console final-byte canary because a
serializer update may change bytes without breaking its Python API.

The raw JSON patch remains narrow while upstream lacks
`dependencies[].provides` support (CycloneDX Python issue 691) and a modeled certificate
serial number. Either patch must be deleted when the library exposes the corresponding
typed field and equivalent bytes have been proven.

## Alternatives considered

Keeping 1.6 was rejected because 1.7 validation is proven and 1.7 has the native
certificate serial field required by this output.

Keeping the endpoint-to-OpenSSL dependency was rejected because it attributes a local
collector implementation to the remote asset without observation.

Fetching the certificate during rendering was rejected because it creates a second,
time-separated observation and can make one scan result produce different CBOM facts.

## Related

- Issue #31 — CycloneDX 1.7 producer and deterministic-reference contract
- Issue #32 — independent CBOM conformance gate
- ADR 0005 — schema source-of-truth decision retained except where superseded above
