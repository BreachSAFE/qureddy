# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-neutral cryptographic identity and classification catalog."""

from __future__ import annotations

from qureddy.core.crypto_catalog.compiler import (
    CatalogCompileError,
    compile_catalog,
)
from qureddy.core.crypto_catalog.models import (
    AlgorithmFacts,
    AlgorithmSpec,
    AlgorithmUse,
    CatalogDefinition,
    CatalogReceipt,
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
)
from qureddy.core.crypto_catalog.snapshot import CryptoCatalogSnapshot

__all__ = [
    "AlgorithmFacts",
    "AlgorithmSpec",
    "AlgorithmUse",
    "CatalogCompileError",
    "CatalogDefinition",
    "CatalogReceipt",
    "Classification",
    "ComponentRole",
    "CryptoCatalogSnapshot",
    "CryptoPrimitive",
    "DigestScope",
    "EntryKind",
    "Identifier",
    "MatchStatus",
    "Protocol",
    "ProtocolEntry",
    "Rating",
    "RatingAxis",
    "RatingVerdict",
    "SourceRecord",
    "SourceRef",
    "compile_catalog",
]
