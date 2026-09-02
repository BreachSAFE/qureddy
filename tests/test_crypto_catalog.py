# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the protocol-neutral crypto catalog runtime."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import FrozenInstanceError
from datetime import date
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from qureddy.core.crypto_catalog import (
    AlgorithmFacts,
    AlgorithmSpec,
    AlgorithmUse,
    CatalogCompileError,
    CatalogDefinition,
    Classification,
    ComponentRole,
    CryptoPrimitive,
    DigestScope,
    EntryKind,
    Identifier,
    MatchStatus,
    Protocol,
    ProtocolEntry,
    Rating,
    RatingAxis,
    RatingVerdict,
    SourceRecord,
    SourceRef,
    compile_catalog,
)

_DIGEST = "0" * 64


def _source() -> SourceRecord:
    return SourceRecord(
        id="source.fixture",
        kind="test-vector",
        title="Catalog contract fixture",
        uri="https://example.invalid/catalog-fixture",
        release="1",
        retrieved=date(2026, 9, 2),
        sha256=_DIGEST,
        license="Apache-2.0",
    )


def _source_ref() -> SourceRef:
    return SourceRef(source_id="source.fixture", locator="vector-1")


def _definition() -> CatalogDefinition:
    quantum_rating = Rating(
        axis=RatingAxis.QUANTUM,
        verdict=RatingVerdict.QUANTUM_VULNERABLE,
        posture_id="crypto.quantum_vulnerable",
        reason_codes=("classical_key_agreement",),
        source_refs=(_source_ref(),),
    )
    return CatalogDefinition(
        registry_id="qureddy-crypto-registry",
        registry_version="fixture-1",
        sources=(_source(),),
        algorithms=(
            AlgorithmSpec(
                id="x25519",
                name="X25519",
                identifiers=(Identifier(namespace="standard-name", value="X25519"),),
                facts=AlgorithmFacts(
                    primitive=CryptoPrimitive.KEY_AGREE,
                    classical_security_level=128,
                    nist_quantum_security_level=0,
                    curve="curve25519",
                ),
                fact_source_refs=(_source_ref(),),
                ratings=(quantum_rating,),
            ),
            AlgorithmSpec(
                id="ml-kem-768",
                name="ML-KEM-768",
                identifiers=(Identifier(namespace="standard-name", value="ML-KEM-768"),),
                facts=AlgorithmFacts(
                    primitive=CryptoPrimitive.KEM,
                    nist_quantum_security_level=3,
                    parameter_set_identifier="ML-KEM-768",
                ),
                fact_source_refs=(_source_ref(),),
            ),
        ),
        protocol_entries=(
            ProtocolEntry(
                id="tls.x25519mlkem768",
                protocol=Protocol.TLS,
                kind=EntryKind.KEY_EXCHANGE,
                identifiers=(
                    Identifier(
                        namespace="openssl-group",
                        value="X25519MLKEM768",
                        case_sensitive=False,
                    ),
                ),
                algorithms=(
                    AlgorithmUse(
                        role=ComponentRole.TRADITIONAL_COMPONENT,
                        algorithm_id="x25519",
                    ),
                    AlgorithmUse(
                        role=ComponentRole.POST_QUANTUM_COMPONENT,
                        algorithm_id="ml-kem-768",
                    ),
                ),
            ),
            ProtocolEntry(
                id="ikev2.ke.36",
                protocol=Protocol.IKE,
                kind=EntryKind.KEY_EXCHANGE,
                identifiers=(Identifier(namespace="iana-ikev2.ke", value="36"),),
                algorithms=(
                    AlgorithmUse(
                        role=ComponentRole.POST_QUANTUM_COMPONENT,
                        algorithm_id="ml-kem-768",
                    ),
                ),
            ),
        ),
    )


def test_compile_builds_immutable_indexes_and_deterministic_receipt() -> None:
    definition = _definition()

    first = compile_catalog(definition)
    second = compile_catalog(definition)

    assert isinstance(first.algorithms_by_id, MappingProxyType)
    assert isinstance(first.protocol_entries_by_id, MappingProxyType)
    assert first.receipt == second.receipt
    assert first.receipt.digest_scope is DigestScope.CANONICAL_DEFINITION
    assert len(first.receipt.sha256) == 64
    with pytest.raises(TypeError):
        first.algorithms_by_id["new"] = definition.algorithms[0]  # type: ignore[index]  # Exercise the runtime mapping guard.
    with pytest.raises(FrozenInstanceError):
        first.receipt = second.receipt  # type: ignore[misc]  # Exercise the runtime frozen guard.


def test_explicit_content_digest_is_identified_as_published_bytes() -> None:
    catalog = compile_catalog(_definition(), content_sha256=_DIGEST)

    assert catalog.receipt.sha256 == _DIGEST
    assert catalog.receipt.digest_scope is DigestScope.PUBLISHED_BYTES


def test_published_digest_scope_requires_supplied_bytes_digest() -> None:
    with pytest.raises(CatalogCompileError) as caught:
        compile_catalog(_definition(), digest_scope=DigestScope.PUBLISHED_BYTES)

    assert caught.value.code == "missing_published_digest"


def test_exact_lookup_preserves_cross_protocol_composition() -> None:
    catalog = compile_catalog(_definition())

    tls = catalog.classify(Protocol.TLS, "openssl-group", "x25519mlkem768")
    tls_original_case = catalog.classify(Protocol.TLS, "openssl-group", "X25519MLKEM768")
    ike = catalog.classify(Protocol.IKE, "iana-ikev2.ke", "36")

    assert tls.match_status is MatchStatus.EXACT
    assert tls.protocol_entry_id == "tls.x25519mlkem768"
    assert tls.algorithm_ids == ("x25519", "ml-kem-768")
    assert [rating.verdict for rating in tls.ratings] == [RatingVerdict.QUANTUM_VULNERABLE]
    assert tls_original_case.protocol_entry_id == tls.protocol_entry_id
    assert ike.match_status is MatchStatus.EXACT
    assert ike.protocol_entry_id == "ikev2.ke.36"
    assert ike.algorithm_ids == ("ml-kem-768",)
    assert ike.ratings == ()
    resolved = catalog.resolve_algorithm("standard-name", "X25519")
    assert resolved is not None
    assert resolved.id == "x25519"


def test_unknown_identifier_is_lossless_and_cannot_create_a_rating() -> None:
    catalog = compile_catalog(_definition())

    classified = catalog.classify(Protocol.IKE, "iana-ikev2.ke", "65000")

    assert classified.match_status is MatchStatus.UNKNOWN
    assert classified.raw_identifier == "65000"
    assert classified.protocol_entry_id is None
    assert classified.algorithm_ids == ()
    assert classified.ratings == ()


def test_classification_status_cannot_claim_inconsistent_content() -> None:
    receipt = compile_catalog(_definition()).receipt

    with pytest.raises(ValidationError, match="unknown match cannot carry resolved content"):
        Classification(
            match_status=MatchStatus.UNKNOWN,
            protocol=Protocol.IKE,
            namespace="iana-ikev2.ke",
            raw_identifier="65000",
            algorithm_ids=("ml-kem-768",),
            receipt=receipt,
        )
    with pytest.raises(ValidationError, match="exact match requires"):
        Classification(
            match_status=MatchStatus.EXACT,
            protocol=Protocol.IKE,
            namespace="iana-ikev2.ke",
            raw_identifier="36",
            protocol_entry_id="ikev2.ke.36",
            receipt=receipt,
        )
    with pytest.raises(ValidationError, match="family-only match cannot carry"):
        Classification(
            match_status=MatchStatus.FAMILY_ONLY,
            protocol=Protocol.IKE,
            namespace="iana-ikev2.ke",
            raw_identifier="36",
            protocol_entry_id="ikev2.ke.36",
            receipt=receipt,
        )


def test_models_reject_unknown_fields_and_invalid_quantum_levels() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AlgorithmFacts.model_validate({"primitive": "kem", "private_rating": "safe"})
    with pytest.raises(ValidationError, match="less_than_equal"):
        AlgorithmFacts(
            primitive=CryptoPrimitive.KEM,
            nist_quantum_security_level=7,
        )
    assert (
        AlgorithmFacts(
            primitive=CryptoPrimitive.OTHER,
            nist_quantum_security_level=6,
        ).nist_quantum_security_level
        == 6
    )
    with pytest.raises(ValidationError, match="source URI must be absolute"):
        SourceRecord.model_validate({**_source().model_dump(), "uri": "relative/source"})
    with pytest.raises(ValidationError, match="control character"):
        Identifier(namespace="wire-name", value="invalid\nidentifier")


def test_algorithm_facts_require_provenance() -> None:
    with pytest.raises(ValidationError, match="facts require at least one source reference"):
        AlgorithmSpec(
            id="unproven",
            name="Unproven",
            facts=AlgorithmFacts(primitive=CryptoPrimitive.UNKNOWN),
        )


def test_rating_verdict_must_match_its_axis() -> None:
    with pytest.raises(ValidationError, match="verdict is invalid for the rating axis"):
        Rating(
            axis=RatingAxis.QUANTUM,
            verdict=RatingVerdict.CLASSICALLY_WEAK,
            posture_id="crypto.invalid",
            reason_codes=("invalid_axis",),
            source_refs=(_source_ref(),),
        )


def test_one_owner_cannot_publish_two_ratings_on_the_same_axis() -> None:
    rating = _definition().algorithms[0].ratings[0]

    with pytest.raises(ValidationError, match="rating axes must be unique"):
        AlgorithmSpec(
            id="duplicate-rating-axis",
            name="Duplicate rating axis",
            ratings=(rating, rating),
        )


def test_protocol_component_roles_are_unique() -> None:
    use = AlgorithmUse(role=ComponentRole.KEY_ESTABLISHMENT, algorithm_id="x25519")

    with pytest.raises(ValidationError, match="algorithm roles must be unique"):
        ProtocolEntry(
            id="tls.duplicate-role",
            protocol=Protocol.TLS,
            kind=EntryKind.KEY_EXCHANGE,
            identifiers=(Identifier(namespace="tls-group", value="duplicate"),),
            algorithms=(use, use),
        )

    rating = _definition().algorithms[0].ratings[0]
    with pytest.raises(ValidationError, match="rating axes must be unique"):
        ProtocolEntry(
            id="tls.duplicate-rating-axis",
            protocol=Protocol.TLS,
            kind=EntryKind.KEY_EXCHANGE,
            identifiers=(Identifier(namespace="tls-group", value="duplicate"),),
            algorithms=(use,),
            ratings=(rating, rating),
        )


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (
            lambda definition: definition.model_copy(
                update={"algorithms": (*definition.algorithms, definition.algorithms[0])}
            ),
            "duplicate_algorithm_id",
        ),
        (
            lambda definition: definition.model_copy(
                update={
                    "algorithms": (
                        *definition.algorithms,
                        definition.algorithms[0].model_copy(update={"id": "duplicate-alias"}),
                    )
                }
            ),
            "duplicate_algorithm_identifier",
        ),
        (
            lambda definition: definition.model_copy(
                update={
                    "algorithms": (
                        definition.algorithms[0].model_copy(
                            update={
                                "fact_source_refs": (
                                    SourceRef(source_id="source.missing", locator="claim"),
                                )
                            }
                        ),
                        *definition.algorithms[1:],
                    )
                }
            ),
            "unresolved_source_reference",
        ),
        (
            lambda definition: definition.model_copy(
                update={
                    "protocol_entries": (
                        *definition.protocol_entries,
                        definition.protocol_entries[0].model_copy(
                            update={"id": "tls.duplicate-alias"}
                        ),
                    )
                }
            ),
            "duplicate_protocol_identifier",
        ),
        (
            lambda definition: definition.model_copy(
                update={
                    "protocol_entries": (
                        definition.protocol_entries[0].model_copy(
                            update={
                                "algorithms": (
                                    AlgorithmUse(
                                        role=ComponentRole.POST_QUANTUM_COMPONENT,
                                        algorithm_id="missing",
                                    ),
                                )
                            }
                        ),
                    )
                }
            ),
            "unresolved_algorithm_reference",
        ),
    ],
)
def test_compiler_rejects_ambiguous_or_unresolved_graphs(
    mutator: Callable[[CatalogDefinition], CatalogDefinition],
    code: str,
) -> None:
    changed = mutator(_definition())

    with pytest.raises(CatalogCompileError) as caught:
        compile_catalog(changed)

    assert caught.value.code == code
    assert caught.value.path


def test_compiler_rejects_conflicting_case_policy_within_a_namespace() -> None:
    definition = _definition()
    conflicting = definition.protocol_entries[0].model_copy(
        update={
            "id": "tls.case-conflict",
            "identifiers": (
                Identifier(
                    namespace="openssl-group",
                    value="OtherGroup",
                    case_sensitive=True,
                ),
            ),
        }
    )
    changed = definition.model_copy(
        update={"protocol_entries": (*definition.protocol_entries, conflicting)}
    )

    with pytest.raises(CatalogCompileError) as caught:
        compile_catalog(changed)

    assert caught.value.code == "identifier_case_policy_conflict"
