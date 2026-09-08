# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bulk-cipher strength and CycloneDX primitive, resolved from the suite name (#315).

A cipher suite name is a packed record. This module decodes exactly one of its
fields and answers three independent questions about it.

  1. Name layout
  ================================================================

      ECDHE  -  RSA  -  AES128GCM  -  SHA256
      +--------+--------+-----------+--------+
      |   kx   |  auth  |   bulk    |  mac   |
      +--------+--------+-----------+--------+
           |        |         |          |
           |        |         |          +--> digest adapter
           |        |         +-------------> THIS MODULE
           |        +-----------------------> signature adapter
           +--------------------------------> key-exchange adapter

  2. Three outputs, independently derived
  ================================================================

      cipher name
           |
           +--> cipher_classical_bits()  -> int | None   strength in bits
           +--> cipher_primitive()       -> str          CycloneDX class
           +--> has_weak_cipher()        -> bool         prohibition verdict

  A name may carry a sourced strength, a known primitive, and a weak verdict
  at the same time. RC4 returns 128 and is prohibited. Consumers that rank or
  filter must read strength and verdict together; strength alone will pass a
  banned suite.

  3. Resolution order
  ================================================================

  Matching is substring-based, so a name can satisfy several rules. Order
  decides which one wins, at two levels.

      cipher_classical_bits(name)
           |
           v
      +----------------------------------------------------------+
      | normalise: lowercase, "_" -> "-"                          |
      +----------------------------------------------------------+
           |
           v
      +----------------------------------------------------------+
      | exact: "none"                              -> 0           |
      +----------------------------------------------------------+
           |  fall through
           v
      +----------------------------------------------------------+
      | PASS 1  _PRE_FAMILY_BITS      ORDER SIGNIFICANT           |
      |         policy caps and prefixes that must beat a         |
      |         substring of their own name                       |
      |         "export1024" must resolve above "export"          |
      +----------------------------------------------------------+
           |  fall through
           v
      +----------------------------------------------------------+
      | PASS 2  _SIZED_FAMILIES       order free                  |
      |         size carried in the name: aes128, aria-256,       |
      |         twofish192-ctr, serpent256-cbc                    |
      +----------------------------------------------------------+
           |  fall through
           v
      +----------------------------------------------------------+
      | PASS 3  _POST_FAMILY_BITS     order free                  |
      |         one fixed size per family: seed, idea, rc4,       |
      |         rc2, cast128, des                                 |
      +----------------------------------------------------------+
           |  fall through
           v
         None

  Reversing the pass sequence misrates DES-CBC3-SHA, EXP-RC4-MD5 and
  EXP1024-RC4-SHA. `WEAK_CIPHER_MARKERS` is order-independent: it is a
  membership test over a fixed set, evaluated in full.

  4. What each output means downstream
  ================================================================

      cipher_classical_bits()  --> cbom_cipher --> classicalSecurityLevel
      cipher_primitive()       --> cbom_cipher --> primitive
      has_weak_cipher()        --> legacy finding + legacy component verdict

  Schema constraints, CycloneDX 1.7:

      classicalSecurityLevel   {"type": "integer", "minimum": 0}, optional
      primitive                closed enum, sixteen members

  NULL therefore rates 0. Zero confidentiality is a measured fact and the
  field accepts 0. NULL maps to `other`, which the schema glosses as "another
  primitive type". The schema reserves `unknown` for a primitive it calls
  unidentified, and a NULL suite is identified exactly.

  5. Absent strength is a defined outcome
  ================================================================

  `cipher_classical_bits()` returns None until a reviewed source assigns the
  name a strength. The caller emits the component and omits the field. An
  inferred figure reads as a measurement once serialised.

  Strength and primitive resolve independently, and `blowfish-cbc` shows the
  gap. RFC 4253 s6.3 lists it, which fixes the primitive at `block-cipher`,
  and the same line states a key size for every neighbouring entry while
  leaving Blowfish without one. Primitive resolves, strength stays None. Keep
  the two answers separate.

  6. Out of scope
  ================================================================

  Forward secrecy, MAC strength, AEAD status and `nistQuantumSecurityLevel`.
  A static-RSA suite carrying AES-256-GCM rates 256 here and clears the marker
  set, so a caller reading this module alone sees a strong cipher.

  Sources
  ================================================================

      SP 800-57 Pt 1 Rev 5  https://doi.org/10.6028/NIST.SP.800-57pt1r5
      RFC 7465 s2           https://www.rfc-editor.org/rfc/rfc7465#section-2
      RFC 5469 s4           https://www.rfc-editor.org/rfc/rfc5469#section-4
      RFC 4253 s6.3         https://www.rfc-editor.org/rfc/rfc4253#section-6.3
      RFC 4344              https://www.rfc-editor.org/rfc/rfc4344
      CycloneDX 1.7         https://cyclonedx.org/docs/1.7/
      Rating policy         docs/architecture/weak-cipher-classification-adr.md

  SP 800-57 Table 2 assigns a security strength to AES and 3DES. RC4, RC2,
  IDEA, SEED, Camellia, ARIA, Twofish, Serpent and CAST-128 fall outside it,
  and their figure is the key length the name carries, capped by export policy
  where one applies. The SSH families print that figure beside the name:
  RFC 4253 s6.3 for the CBC spellings, RFC 4344 for SDCTR.
"""

from __future__ import annotations

WEAK_CIPHER_MARKERS: tuple[str, ...] = (
    "3DES",
    "DES",
    "RC4",
    "RC2",
    "NULL",
    "EXPORT",
    "MD5",
    "ADH",
    "AECDH",
)


def _sized_family_bits(lowered: str, family: str) -> int | None:
    """Resolve a supported family-size spelling from a normalized suite name.

    Only spellings used by the supported cipher inventories are accepted. The helper
    returns ``None`` for an unrecognized spelling; callers then continue to the next
    reviewed rule. It never guesses a size from an arbitrary digit in a future name.
    """
    for size in (256, 192, 128):
        if (
            f"{family}{size}" in lowered
            or f"{family}-{size}" in lowered
            or f"{family}_{size}" in lowered
            or (family in lowered and lowered.endswith((f"_{size}", f"-{size}")))
        ):
            return size
    return None


# Pass 1 of 3: rows that have to win against a substring of their own name.
_PRE_FAMILY_BITS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("chacha20",), 256),
    (("rc4-64",), 64),
    (("exp1024",), 56),
    (("export1024",), 56),
    (("exp-", "export"), 40),
    # RFC 4253 s6.3 defines "twofish-cbc" as an alias for "twofish256-cbc",
    # retained for historical reasons. The alias carries no digits, so it
    # resolves here; the sized spellings fall to pass 2.
    (("twofish-cbc",), 256),
    # NULL suites explicitly describe no confidentiality; retain a rated zero
    # instead of treating the observation as an unknown algorithm.
    (("null",), 0),
    (("3des", "des-cbc3"), 112),
)

# Pass 2 of 3: size is in the name. Twofish and Serpent carry theirs in the
# RFC 4253 s6.3 CBC names and the RFC 4344 SDCTR names alike.
_SIZED_FAMILIES: tuple[str, ...] = (
    "aes",
    "camellia",
    "aria",
    "arcfour",
    "twofish",
    "serpent",
)

# Pass 3 of 3: one size per family. RC4 and RC2 are the non-export forms.
_POST_FAMILY_BITS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("seed",), 128),
    (("idea",), 128),  # RFC 5469 s4.2 withdraws it; absent from WEAK_CIPHER_MARKERS
    (("rc4", "arcfour"), 128),
    (("rc2",), 128),
    (("cast128",), 128),  # RFC 4344 line 200 states the 128-bit key for cast128-ctr
    (("des",), 56),
)

# Keep these rules ordered: NULL must become ``other`` before generic AE/block
# matching, and an unrecognized name must remain ``unknown`` rather than acquire
# a guessed primitive. The future registry will replace this transitional table.
_PRIMITIVE_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("null",), "other"),
    (("gcm", "chacha20-poly1305", "ccm"), "ae"),
    (("chacha20",), "stream-cipher"),
    (("rc4", "arcfour"), "stream-cipher"),
    (
        (
            "aes",
            "camellia",
            "aria",
            "seed",
            "idea",
            "rc2",
            "des",
            "blowfish",
            "cast128",
            "twofish",
            "serpent",
            "rijndael",
            "gost2001-gost89",
            "gost94-gost89",
        ),
        "block-cipher",
    ),
)


def _first_marker_bits(lowered: str, rules: tuple[tuple[tuple[str, ...], int], ...]) -> int | None:
    """Return the first ordered rule match, preserving classification precedence.

    Export and 3DES names contain ordinary cipher markers, so callers place their
    disambiguating rules before generic family rules. ``None`` means no rule in the
    supplied table has a sourced rating.
    """
    for markers, bits in rules:
        if any(marker in lowered for marker in markers):
            return bits
    return None


def _normalise_cipher_name(name: str) -> str:
    """Canonicalize case and protocol separator spelling before classification."""
    return name.lower().replace("_", "-")


def cipher_classical_bits(name: str) -> int | None:
    """Return sourced classical strength in bits, or ``None`` without a mapping.

    ``None`` records an observed algorithm with no reviewed strength. CBOM callers
    preserve the component and omit ``classicalSecurityLevel``; they do not convert
    uncertainty into zero or a guessed value. Rule order handles export and 3DES
    names before their generic markers.
    """
    lowered = _normalise_cipher_name(name)
    # SSH defines ``none`` as a complete algorithm identifier, not a family
    # marker. Keep it exact so names such as ``hmac-none`` remain unknown.
    if lowered == "none":
        return 0
    # ENCR_3IDEA identifies a family without a reviewed strength. Resolve it
    # before the generic IDEA row so the CBOM retains the observation while
    # omitting an unsupported classicalSecurityLevel.
    if "3idea" in lowered:
        return None
    bits = _first_marker_bits(lowered, _PRE_FAMILY_BITS)
    if bits is not None:
        return bits
    for family in _SIZED_FAMILIES:
        bits = _sized_family_bits(lowered, family)
        if bits is not None:
            return bits
    return _first_marker_bits(lowered, _POST_FAMILY_BITS)


def cipher_primitive(name: str) -> str:
    """Return the protocol-neutral primitive, or ``unknown`` without a mapping.

    The result is consumed by the CycloneDX adapter and SSH classification. An
    unrecognized name remains ``unknown`` so downstream CBOM output cannot imply a
    cipher family that this table did not establish.
    """
    lowered = _normalise_cipher_name(name)
    # The shared table uses family substrings; SSH ``none`` is an exact alias
    # for NULL and must not classify unrelated names containing that spelling.
    if lowered == "none":
        return "other"
    # A NULL suite encrypts nothing, so no cipher primitive describes it. The
    # CycloneDX enum has no "none" member, so "other" is the projection.
    return next(
        (
            primitive
            for markers, primitive in _PRIMITIVE_RULES
            if any(marker in lowered for marker in markers)
        ),
        "unknown",
    )


def weak_ciphers(accepted_ciphers: tuple[str, ...]) -> tuple[str, ...]:
    """Return accepted suites matching the reviewed weak-cipher markers."""
    return tuple(
        cipher
        for cipher in accepted_ciphers
        if cipher.upper() == "NONE"
        or any(marker in cipher.upper() for marker in WEAK_CIPHER_MARKERS)
    )


def has_weak_cipher(accepted_ciphers: tuple[str, ...]) -> bool:
    """Return whether accepted suite names contain a reviewed weak marker.

    This is an acceptance verdict separate from strength and primitive classification.
    A suite can have numeric strength and still return ``True``. The caller owns the
    policy response and finding text; this helper only matches the reviewed markers.
    """
    return bool(weak_ciphers(accepted_ciphers))
