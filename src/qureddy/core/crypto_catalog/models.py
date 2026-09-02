# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Typed entities shared by built-in and published crypto catalogs."""

from __future__ import annotations

import re
from datetime import date
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_STABLE_ID = r"^[a-z][a-z0-9_.-]{0,127}$"
_SHA256 = r"^[0-9a-f]{64}$"
_FIRST_CONTROL_CODE = 32
_DELETE_CODE = 127
StableId = Annotated[str, Field(pattern=_STABLE_ID)]
ShortText = Annotated[str, Field(min_length=1, max_length=256)]


class CryptoPrimitive(StrEnum):
    """CycloneDX 1.7 crypto primitive vocabulary."""

    AE = "ae"
    BLOCK_CIPHER = "block-cipher"
    COMBINER = "combiner"
    DRBG = "drbg"
    HASH = "hash"
    KDF = "kdf"
    KEM = "kem"
    KEY_AGREE = "key-agree"
    KEY_WRAP = "key-wrap"
    MAC = "mac"
    PKE = "pke"
    SIGNATURE = "signature"
    STREAM_CIPHER = "stream-cipher"
    XOF = "xof"
    OTHER = "other"
    UNKNOWN = "unknown"


class Protocol(StrEnum):
    """Protocol families with catalog identities."""

    TLS = "tls"
    SSH = "ssh"
    IKE = "ike"
    CERTIFICATE = "certificate"


class EntryKind(StrEnum):
    """Semantic kinds of protocol entry."""

    CIPHER_SUITE = "cipher_suite"
    KEY_EXCHANGE = "key_exchange"
    HOST_KEY = "host_key"
    CIPHER = "cipher"
    MAC = "mac"
    PUBLIC_KEY = "public_key"
    PRF = "prf"
    INTEGRITY = "integrity"


class ComponentRole(StrEnum):
    """Role played by an algorithm inside a protocol entry."""

    KEY_ESTABLISHMENT = "key_establishment"
    CONFIDENTIALITY = "confidentiality"
    AUTHENTICATION = "authentication"
    INTEGRITY = "integrity"
    PRF = "prf"
    TRADITIONAL_COMPONENT = "traditional_component"
    POST_QUANTUM_COMPONENT = "post_quantum_component"


class RatingAxis(StrEnum):
    """Independent interpretation axes."""

    CLASSICAL = "classical"
    QUANTUM = "quantum"
    DEPLOYMENT = "deployment"


class RatingVerdict(StrEnum):
    """Catalog rating outcomes."""

    CLASSICALLY_WEAK = "classically_weak"
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    QUANTUM_SAFE = "quantum_safe"
    DISCOURAGED = "discouraged"
    PROHIBITED = "prohibited"
    UNKNOWN = "unknown"


class MatchStatus(StrEnum):
    """Strength of an observation-to-catalog match."""

    EXACT = "exact"
    FAMILY_ONLY = "family_only"
    UNKNOWN = "unknown"


class DigestScope(StrEnum):
    """Bytes represented by a catalog receipt digest."""

    CANONICAL_DEFINITION = "canonical_definition"
    PUBLISHED_BYTES = "published_bytes"


class CatalogModel(BaseModel):
    """Frozen validation defaults for every catalog entity."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class SourceRef(CatalogModel):
    """Exact location supporting one catalog claim."""

    source_id: StableId
    locator: Annotated[str, Field(min_length=1, max_length=512)]


class SourceRecord(CatalogModel):
    """Pinned source identity retained in the runtime catalog."""

    id: StableId
    kind: StableId
    title: ShortText
    uri: Annotated[str, Field(min_length=1, max_length=2048)]
    release: ShortText
    retrieved: date
    sha256: Annotated[str, Field(pattern=_SHA256)]
    license: ShortText

    @field_validator("uri")
    @classmethod
    def _uri_must_be_absolute(cls, value: str) -> str:
        """Reject relative source locations at the model boundary."""
        if not re.match(r"^[a-z][a-z0-9+.-]*://", value, flags=re.IGNORECASE):
            raise ValueError("source URI must be absolute")
        return value


class Identifier(CatalogModel):
    """Namespaced algorithm or wire identifier with explicit case policy."""

    namespace: StableId
    value: ShortText
    case_sensitive: bool = True

    @field_validator("value")
    @classmethod
    def _value_must_not_contain_controls(cls, value: str) -> str:
        """Reject control characters before an identifier reaches a lookup."""
        if any(
            ord(character) < _FIRST_CONTROL_CODE or ord(character) == _DELETE_CODE
            for character in value
        ):
            raise ValueError("identifier value contains a control character")
        return value


class AlgorithmFacts(CatalogModel):
    """Protocol-neutral facts using CycloneDX names where available."""

    primitive: CryptoPrimitive | None = None
    classical_security_level: int | None = Field(
        default=None,
        serialization_alias="classicalSecurityLevel",
        ge=0,
    )
    nist_quantum_security_level: int | None = Field(
        default=None,
        serialization_alias="nistQuantumSecurityLevel",
        ge=0,
        le=6,
    )
    parameter_set_identifier: ShortText | None = Field(
        default=None,
        serialization_alias="parameterSetIdentifier",
    )
    curve: ShortText | None = None
    block_size_bits: int | None = Field(default=None, ge=1, le=65536)

    def has_claims(self) -> bool:
        """Return whether any fact is asserted."""
        return any(value is not None for value in self.model_dump().values())


class Rating(CatalogModel):
    """Sourced interpretation on one independent rating axis."""

    axis: RatingAxis
    verdict: RatingVerdict
    posture_id: StableId
    reason_codes: tuple[StableId, ...] = Field(min_length=1, max_length=32)
    source_refs: tuple[SourceRef, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def _verdict_must_match_axis(self) -> Rating:
        """Reject verdicts assigned to a contradictory rating axis."""
        allowed = {
            RatingAxis.CLASSICAL: {RatingVerdict.CLASSICALLY_WEAK},
            RatingAxis.QUANTUM: {
                RatingVerdict.QUANTUM_SAFE,
                RatingVerdict.QUANTUM_VULNERABLE,
            },
            RatingAxis.DEPLOYMENT: {
                RatingVerdict.DISCOURAGED,
                RatingVerdict.PROHIBITED,
            },
        }
        if self.verdict is not RatingVerdict.UNKNOWN and self.verdict not in allowed[self.axis]:
            raise ValueError("verdict is invalid for the rating axis")
        return self


def _rating_axes_are_unique(ratings: tuple[Rating, ...]) -> bool:
    """Return whether one owner has at most one rating on each axis."""
    axes = tuple(rating.axis for rating in ratings)
    return len(axes) == len(set(axes))


class AlgorithmSpec(CatalogModel):
    """Reusable algorithm identity, facts, and algorithm-wide ratings."""

    id: StableId
    name: ShortText
    identifiers: tuple[Identifier, ...] = Field(default_factory=tuple, max_length=64)
    facts: AlgorithmFacts = Field(default_factory=AlgorithmFacts)
    fact_source_refs: tuple[SourceRef, ...] = Field(default_factory=tuple, max_length=32)
    ratings: tuple[Rating, ...] = Field(default_factory=tuple, max_length=8)

    @model_validator(mode="after")
    def _claims_must_be_unambiguous(self) -> AlgorithmSpec:
        """Require sourced facts and one rating per independent axis."""
        if self.facts.has_claims() and not self.fact_source_refs:
            raise ValueError("facts require at least one source reference")
        if not _rating_axes_are_unique(self.ratings):
            raise ValueError("rating axes must be unique within one owner")
        return self


class AlgorithmUse(CatalogModel):
    """One constituent algorithm and its role in a protocol entry."""

    role: ComponentRole
    algorithm_id: StableId


class ProtocolEntry(CatalogModel):
    """Exact protocol identity composed from reusable algorithms."""

    id: StableId
    protocol: Protocol
    kind: EntryKind
    identifiers: tuple[Identifier, ...] = Field(min_length=1, max_length=64)
    algorithms: tuple[AlgorithmUse, ...] = Field(min_length=1, max_length=16)
    ratings: tuple[Rating, ...] = Field(default_factory=tuple, max_length=8)

    @model_validator(mode="after")
    def _relationships_must_be_unambiguous(self) -> ProtocolEntry:
        """Require unique component roles and one entry rating per axis."""
        roles = tuple(use.role for use in self.algorithms)
        if len(roles) != len(set(roles)):
            raise ValueError("algorithm roles must be unique within one protocol entry")
        if not _rating_axes_are_unique(self.ratings):
            raise ValueError("rating axes must be unique within one owner")
        return self


class CatalogDefinition(CatalogModel):
    """Source-neutral input compiled into an immutable runtime snapshot."""

    registry_id: StableId
    registry_version: ShortText
    sources: tuple[SourceRecord, ...] = Field(min_length=1, max_length=1024)
    algorithms: tuple[AlgorithmSpec, ...] = Field(min_length=1, max_length=16384)
    protocol_entries: tuple[ProtocolEntry, ...] = Field(min_length=1, max_length=65536)


class CatalogReceipt(CatalogModel):
    """Reproducible identity of the catalog content used for classification."""

    registry_id: StableId
    registry_version: ShortText
    sha256: Annotated[str, Field(pattern=_SHA256)]
    digest_scope: DigestScope


class Classification(CatalogModel):
    """Lossless catalog resolution result for one observed identifier."""

    match_status: MatchStatus
    protocol: Protocol
    namespace: StableId
    raw_identifier: ShortText
    protocol_entry_id: StableId | None = None
    algorithm_ids: tuple[StableId, ...] = Field(default_factory=tuple, max_length=16)
    ratings: tuple[Rating, ...] = Field(default_factory=tuple, max_length=64)
    receipt: CatalogReceipt

    @model_validator(mode="after")
    def _exact_match_requires_resolved_content(self) -> Classification:
        """Require exact matches to identify an entry and its algorithms."""
        missing_content = self.protocol_entry_id is None or not self.algorithm_ids
        if self.match_status is MatchStatus.EXACT and missing_content:
            raise ValueError("exact match requires a protocol entry and algorithms")
        return self

    @model_validator(mode="after")
    def _family_match_excludes_exact_content(self) -> Classification:
        """Prevent family-only matches from claiming an entry or ratings."""
        has_exact_content = self.protocol_entry_id is not None or bool(self.ratings)
        if self.match_status is MatchStatus.FAMILY_ONLY and has_exact_content:
            raise ValueError("family-only match cannot carry an entry or ratings")
        return self

    @model_validator(mode="after")
    def _unknown_match_excludes_resolved_content(self) -> Classification:
        """Prevent unknown matches from carrying any resolved catalog content."""
        has_resolved_content = (
            self.protocol_entry_id is not None or bool(self.algorithm_ids) or bool(self.ratings)
        )
        if self.match_status is MatchStatus.UNKNOWN and has_resolved_content:
            raise ValueError("unknown match cannot carry resolved content")
        return self
