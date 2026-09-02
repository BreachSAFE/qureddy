# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Compile validated crypto catalog entities into immutable lookup indexes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Hashable, Mapping

from qureddy.core.crypto_catalog.models import (
    AlgorithmSpec,
    CatalogDefinition,
    CatalogReceipt,
    DigestScope,
    Identifier,
    ProtocolEntry,
    Rating,
    SourceRecord,
    SourceRef,
)
from qureddy.core.crypto_catalog.snapshot import (
    AlgorithmIdentity,
    CryptoCatalogSnapshot,
    ProtocolIdentity,
    ProtocolNamespace,
)


class CatalogCompileError(ValueError):
    """A stable, path-addressed semantic catalog validation failure."""

    def __init__(self, code: str, path: str, message: str) -> None:
        """Record a stable error code and path before formatting the message."""
        self.code = code
        self.path = path
        super().__init__(f"{code} at {path}: {message}")


def _canonical_sha256(definition: CatalogDefinition) -> str:
    """Return a deterministic digest for an in-memory catalog definition."""
    data = definition.model_dump(mode="json", by_alias=True, exclude_none=True)
    canonical = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _add_unique[Value](
    index: dict[str, Value],
    key: str,
    value: Value,
    *,
    code: str,
    path: str,
) -> None:
    """Add one canonical ID or raise a stable duplicate error."""
    if key in index:
        raise CatalogCompileError(code, path, f"duplicate identifier {key!r}")
    index[key] = value


def _register_case_policy[Namespace: Hashable](
    policies: dict[Namespace, bool],
    namespace: Namespace,
    identifier: Identifier,
    *,
    path: str,
) -> None:
    """Require one case policy for every identifier namespace."""
    current = policies.get(namespace)
    if current is not None and current != identifier.case_sensitive:
        raise CatalogCompileError(
            "identifier_case_policy_conflict",
            path,
            "one namespace must use one case policy",
        )
    policies[namespace] = identifier.case_sensitive


def _normalized(identifier: Identifier) -> str:
    """Normalize one identifier according to its declared case policy."""
    return identifier.value if identifier.case_sensitive else identifier.value.casefold()


def _validate_source_ref(source_ids: set[str], source_ref: SourceRef, *, path: str) -> None:
    """Require one source reference to resolve inside the same definition."""
    if source_ref.source_id not in source_ids:
        raise CatalogCompileError(
            "unresolved_source_reference",
            path,
            f"source {source_ref.source_id!r} does not exist",
        )


def _validate_ratings(source_ids: set[str], ratings: tuple[Rating, ...], *, path: str) -> None:
    """Require every rating source reference to resolve atomically."""
    for rating_index, rating in enumerate(ratings):
        for ref_index, source_ref in enumerate(rating.source_refs):
            _validate_source_ref(
                source_ids,
                source_ref,
                path=f"{path}.ratings[{rating_index}].source_refs[{ref_index}]",
            )


def _compile_algorithms(
    definition: CatalogDefinition,
    source_ids: set[str],
) -> tuple[dict[str, AlgorithmSpec], dict[AlgorithmIdentity, AlgorithmSpec], dict[str, bool]]:
    """Compile canonical algorithm and alias indexes."""
    algorithms: dict[str, AlgorithmSpec] = {}
    identities: dict[AlgorithmIdentity, AlgorithmSpec] = {}
    policies: dict[str, bool] = {}
    for index, algorithm in enumerate(definition.algorithms):
        path = f"algorithms[{index}]"
        _add_unique(
            algorithms,
            algorithm.id,
            algorithm,
            code="duplicate_algorithm_id",
            path=f"{path}.id",
        )
        for ref_index, source_ref in enumerate(algorithm.fact_source_refs):
            _validate_source_ref(
                source_ids,
                source_ref,
                path=f"{path}.fact_source_refs[{ref_index}]",
            )
        _validate_ratings(source_ids, algorithm.ratings, path=path)
        for identifier_index, identifier in enumerate(algorithm.identifiers):
            identifier_path = f"{path}.identifiers[{identifier_index}]"
            _register_case_policy(policies, identifier.namespace, identifier, path=identifier_path)
            key = (identifier.namespace, _normalized(identifier))
            if key in identities:
                raise CatalogCompileError(
                    "duplicate_algorithm_identifier",
                    identifier_path,
                    f"identifier {key!r} is already assigned",
                )
            identities[key] = algorithm
    return algorithms, identities, policies


def _compile_protocol_entries(
    definition: CatalogDefinition,
    algorithms: Mapping[str, AlgorithmSpec],
    source_ids: set[str],
) -> tuple[
    dict[str, ProtocolEntry],
    dict[ProtocolIdentity, ProtocolEntry],
    dict[ProtocolNamespace, bool],
]:
    """Compile protocol entries after validating their algorithm graph."""
    entries: dict[str, ProtocolEntry] = {}
    identities: dict[ProtocolIdentity, ProtocolEntry] = {}
    policies: dict[ProtocolNamespace, bool] = {}
    for index, entry in enumerate(definition.protocol_entries):
        path = f"protocol_entries[{index}]"
        _add_unique(
            entries,
            entry.id,
            entry,
            code="duplicate_protocol_entry_id",
            path=f"{path}.id",
        )
        for use_index, use in enumerate(entry.algorithms):
            if use.algorithm_id not in algorithms:
                raise CatalogCompileError(
                    "unresolved_algorithm_reference",
                    f"{path}.algorithms[{use_index}].algorithm_id",
                    f"algorithm {use.algorithm_id!r} does not exist",
                )
        _validate_ratings(source_ids, entry.ratings, path=path)
        for identifier_index, identifier in enumerate(entry.identifiers):
            identifier_path = f"{path}.identifiers[{identifier_index}]"
            namespace = (entry.protocol, identifier.namespace)
            _register_case_policy(policies, namespace, identifier, path=identifier_path)
            key = (entry.protocol, identifier.namespace, _normalized(identifier))
            if key in identities:
                raise CatalogCompileError(
                    "duplicate_protocol_identifier",
                    identifier_path,
                    f"identifier {key!r} is already assigned",
                )
            identities[key] = entry
    return entries, identities, policies


def _build_receipt(
    definition: CatalogDefinition,
    *,
    content_sha256: str | None,
    digest_scope: DigestScope | None,
) -> CatalogReceipt:
    """Bind the catalog identity to canonical definition or published bytes."""
    if content_sha256 is None and digest_scope is DigestScope.PUBLISHED_BYTES:
        raise CatalogCompileError(
            "missing_published_digest",
            "receipt.sha256",
            "published bytes require a caller-supplied digest",
        )
    resolved_scope = digest_scope or (
        DigestScope.PUBLISHED_BYTES
        if content_sha256 is not None
        else DigestScope.CANONICAL_DEFINITION
    )
    return CatalogReceipt(
        registry_id=definition.registry_id,
        registry_version=definition.registry_version,
        sha256=content_sha256 if content_sha256 is not None else _canonical_sha256(definition),
        digest_scope=resolved_scope,
    )


def compile_catalog(
    definition: CatalogDefinition,
    *,
    content_sha256: str | None = None,
    digest_scope: DigestScope | None = None,
) -> CryptoCatalogSnapshot:
    """Validate references and compile one atomic immutable catalog snapshot."""
    sources: dict[str, SourceRecord] = {}
    for index, source in enumerate(definition.sources):
        _add_unique(
            sources,
            source.id,
            source,
            code="duplicate_source_id",
            path=f"sources[{index}].id",
        )
    source_ids = set(sources)
    algorithms, algorithm_identities, algorithm_policies = _compile_algorithms(
        definition,
        source_ids,
    )
    entries, protocol_identities, protocol_policies = _compile_protocol_entries(
        definition,
        algorithms,
        source_ids,
    )
    receipt = _build_receipt(
        definition,
        content_sha256=content_sha256,
        digest_scope=digest_scope,
    )
    return CryptoCatalogSnapshot(
        algorithms_by_id=algorithms,
        algorithm_identifiers=algorithm_identities,
        algorithm_case_policy=algorithm_policies,
        protocol_entries_by_id=entries,
        protocol_identifiers=protocol_identities,
        protocol_case_policy=protocol_policies,
        receipt=receipt,
    )
