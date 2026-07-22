# NIST PQC / CNSA 2.0 timeline reference

**Re-verify before relying on this.** These dates were gathered from a web search and are
believed reasonably current as of when this file was written, but this file is *not* a
primary source and has not been independently re-checked against nist.gov or the exact
publication text. Before using any date here in a real compliance claim, a customer-facing
statement, or an audit response, go re-read the primary source (the specific NIST IR/SP
number, or the CNSA 2.0 fact sheet from NSA/CISA) and confirm the number, the scope
(federal/NSS vs. general industry), and whether it has been superseded.

## Purpose

This table exists to ground "is this proposal building a real PQC migration story"
conversations with rough regulatory pressure/timing context — not to be quoted verbatim as
a compliance deadline. The actual applicability of any of these dates depends heavily on
who the platform's customers are (federal/NSS vs. commercial, regulated vs. not) — that
scoping question matters more than the raw dates and should be asked explicitly rather than
assumed.

## Standards status

| Standard | Algorithm | Status (as researched) |
|---|---|---|
| FIPS 203 | ML-KEM (key encapsulation) | Finalized August 2024 |
| FIPS 204 | ML-DSA (digital signatures) | Finalized August 2024 |
| FIPS 205 | SLH-DSA (stateless hash-based signatures) | Finalized August 2024 |
| FIPS 206 | FN-DSA / FALCON (digital signatures) | In progress, not yet finalized as of this writing |

## Deprecation / mandate pressure

| Source | Claim (as researched) |
|---|---|
| NIST IR 8547 | Deprecates RSA-2048 / ECC P-256 (and similarly-sized classical algorithms) by 2030; states intent to remove quantum-vulnerable algorithms from NIST standards entirely by 2035. |
| CNSA 2.0 (NSA) | New National Security Systems (NSS) acquisitions must be CNSA 2.0-compliant starting January 1, 2027. Broader mandatory compliance across most NSS system categories targeted by 2033. |

## How to use this without overclaiming

- Treat "2030" and "2035" as NIST-standards-track deprecation/removal targets, not as a
  blanket statement that a given customer's systems become non-compliant on that exact
  date — check whether the customer is even in-scope for the source document in question.
- Treat CNSA 2.0 dates as specific to NSS (national security systems) procurement, not
  automatically applicable outside that context — many BQP customers won't be NSS, and
  claiming CNSA 2.0 mandate applicability to a non-NSS customer would be overclaiming.
- When a component's ADR or roadmap uses one of these dates to justify urgency, check that
  the surrounding text doesn't imply a broader mandate than the source actually states —
  this is the kind of "honest interop / no overclaiming" discipline already expected
  elsewhere in this platform's engineering docs, and it applies equally to PM/roadmap
  language.
- If asked to help write customer-facing or compliance-facing language using these dates,
  push back on doing so directly from this file — the request should go find and cite the
  actual primary source at that time, since standards documents get amended/superseded.
