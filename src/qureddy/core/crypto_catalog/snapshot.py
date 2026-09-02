# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Own immutable lookup behavior for a compiled crypto catalog."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from qureddy.core.crypto_catalog.models import (
    AlgorithmSpec,
    CatalogReceipt,
    Classification,
    MatchStatus,
    Protocol,
    ProtocolEntry,
)

AlgorithmIdentity = tuple[str, str]
ProtocolIdentity = tuple[Protocol, str, str]
ProtocolNamespace = tuple[Protocol, str]


@dataclass(frozen=True, slots=True, init=False)
class CryptoCatalogSnapshot:
    """Immutable indexes and receipt used by protocol classifiers."""

    _algorithms_by_id: Mapping[str, AlgorithmSpec]
    _algorithm_identifiers: Mapping[AlgorithmIdentity, AlgorithmSpec]
    _algorithm_case_policy: Mapping[str, bool]
    _protocol_entries_by_id: Mapping[str, ProtocolEntry]
    _protocol_identifiers: Mapping[ProtocolIdentity, ProtocolEntry]
    _protocol_case_policy: Mapping[ProtocolNamespace, bool]
    receipt: CatalogReceipt

    def __init__(
        self,
        *,
        algorithms_by_id: Mapping[str, AlgorithmSpec],
        algorithm_identifiers: Mapping[AlgorithmIdentity, AlgorithmSpec],
        algorithm_case_policy: Mapping[str, bool],
        protocol_entries_by_id: Mapping[str, ProtocolEntry],
        protocol_identifiers: Mapping[ProtocolIdentity, ProtocolEntry],
        protocol_case_policy: Mapping[ProtocolNamespace, bool],
        receipt: CatalogReceipt,
    ) -> None:
        """Freeze defensive copies of all compiled indexes and the receipt."""
        object.__setattr__(self, "_algorithms_by_id", MappingProxyType(dict(algorithms_by_id)))
        object.__setattr__(
            self,
            "_algorithm_identifiers",
            MappingProxyType(dict(algorithm_identifiers)),
        )
        object.__setattr__(
            self,
            "_algorithm_case_policy",
            MappingProxyType(dict(algorithm_case_policy)),
        )
        object.__setattr__(
            self,
            "_protocol_entries_by_id",
            MappingProxyType(dict(protocol_entries_by_id)),
        )
        object.__setattr__(
            self,
            "_protocol_identifiers",
            MappingProxyType(dict(protocol_identifiers)),
        )
        object.__setattr__(
            self,
            "_protocol_case_policy",
            MappingProxyType(dict(protocol_case_policy)),
        )
        object.__setattr__(self, "receipt", receipt)

    @property
    def algorithms_by_id(self) -> Mapping[str, AlgorithmSpec]:
        """Return the immutable canonical algorithm index."""
        return self._algorithms_by_id

    @property
    def protocol_entries_by_id(self) -> Mapping[str, ProtocolEntry]:
        """Return the immutable canonical protocol-entry index."""
        return self._protocol_entries_by_id

    def resolve_algorithm(self, namespace: str, value: str) -> AlgorithmSpec | None:
        """Resolve an algorithm alias under its declared case policy."""
        policy = self._algorithm_case_policy.get(namespace)
        normalized = value if policy is not False else value.casefold()
        return self._algorithm_identifiers.get((namespace, normalized))

    def classify(self, protocol: Protocol, namespace: str, value: str) -> Classification:
        """Resolve one exact protocol identifier without fabricating family facts."""
        policy = self._protocol_case_policy.get((protocol, namespace))
        normalized = value if policy is not False else value.casefold()
        entry = self._protocol_identifiers.get((protocol, namespace, normalized))
        if entry is None:
            return Classification(
                match_status=MatchStatus.UNKNOWN,
                protocol=protocol,
                namespace=namespace,
                raw_identifier=value,
                receipt=self.receipt,
            )
        algorithms = tuple(use.algorithm_id for use in entry.algorithms)
        ratings = (
            tuple(
                rating
                for algorithm_id in algorithms
                for rating in self._algorithms_by_id[algorithm_id].ratings
            )
            + entry.ratings
        )
        return Classification(
            match_status=MatchStatus.EXACT,
            protocol=protocol,
            namespace=namespace,
            raw_identifier=value,
            protocol_entry_id=entry.id,
            algorithm_ids=algorithms,
            ratings=ratings,
            receipt=self.receipt,
        )
