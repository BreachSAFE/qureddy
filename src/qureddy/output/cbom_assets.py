# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared crypto-asset emitter core for the CBOM (#288).

One collect -> dedup-by-strongest-observation -> emit loop that every algorithm-asset
emitter (TLS groups and cipher suites; SSH KEX / host-key / cipher / MAC) calls, so TLS
and SSH emit assets through identical machinery. Protocol-specific classification
(name -> algorithmProperties) and evidence selection are supplied by the caller.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING

from cyclonedx.model import Property
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import AlgorithmProperties, CryptoAssetType, CryptoProperties

from qureddy.core.models import ObservationType

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import Evidence, ScanResult

ENDPOINT_REF = "endpoint"


def add_provides_edge(provides_edges: dict[str, list[str]], ref: str) -> None:
    """Record that the scanned endpoint provides one CBOM component reference."""
    provides_edges.setdefault(ENDPOINT_REF, []).append(ref)


def algorithm_ref(name: str) -> str:
    """Return the bom-ref for an algorithm crypto-asset.

    One grammar shared by every emitter and the metadata/annotation layer (#315), so a ref
    and the component it points at cannot disagree on casing or prefix.
    """
    return f"crypto/algorithm/{name.lower()}"


def protocol_ref(protocol: str, version: str) -> str:
    """The bom-ref for a protocol crypto-asset, e.g. ``crypto/protocol/tls-1.3`` (#315)."""
    return f"crypto/protocol/{protocol}-{version.lower()}"


def select_by_evidence_type(*evidence_types: str) -> Callable[[Evidence], str | None]:
    """Build a ``select`` that yields ``negotiated_group`` only for the given evidence type(s).

    The identical ``lambda e: e.negotiated_group if e.evidence_type == "X" else None`` shape
    repeated across every SSH/legacy asset emitter (#315); this is the one place it lives.
    Emitters selecting a different field (e.g. ``cipher_suite``) or an inverted set keep their
    own inline ``select`` for readability.
    """
    allowed = frozenset(evidence_types)
    return lambda evidence: evidence.negotiated_group if evidence.evidence_type in allowed else None


def select_algorithm_by_evidence_type(*evidence_types: str) -> Callable[[Evidence], str | None]:
    """Select a reported algorithm for the given evidence types."""
    allowed = frozenset(evidence_types)
    return lambda evidence: evidence.algorithm if evidence.evidence_type in allowed else None


def verdict_pairs(
    readiness: str, severity: str, rule_id: str | None = None
) -> list[tuple[str, str]]:
    """Return the ``(name, value)`` pairs for a qureddy verdict block (#315).

    The single home for the ``qureddy:readiness`` / ``qureddy:severity`` / ``qureddy:rule_id``
    property names, so the legacy-cipher emitter (which wraps them as ``Property`` objects) and
    the finding-annotation layer (which wraps them as dicts) cannot disagree on the names.
    ``rule_id`` is omitted when None so callers that carry only readiness/severity get exactly
    those two pairs, in that order.
    """
    pairs = [("qureddy:readiness", readiness), ("qureddy:severity", severity)]
    if rule_id is not None:
        pairs.append(("qureddy:rule_id", rule_id))
    return pairs


POSITIVE_OBSERVATIONS = frozenset(
    {ObservationType.NEGOTIATED, ObservationType.OFFERED, ObservationType.OBSERVED}
)


# Strongest-signal ordering: a group seen negotiated outranks one merely offered or
# observed on a control probe, so the CBOM records the actual handshake outcome (#150).
OBSERVATION_RANK: MappingProxyType[ObservationType, int] = MappingProxyType(
    {
        ObservationType.OBSERVED: 0,
        ObservationType.OFFERED: 1,
        ObservationType.NEGOTIATED: 2,
    }
)


def add_algorithm_assets(
    bom: Bom,
    result: ScanResult,
    provides_edges: dict[str, list[str]],
    *,
    select: Callable[[Evidence], str | None],
    algorithm_properties: Callable[[str], AlgorithmProperties | None],
    extra_properties: Callable[[str], list[Property]] | None = None,
) -> dict[str, str]:
    """Emit one ALGORITHM crypto-asset per uniquely named thing ``select`` returns.

    The single collect -> dedup-by-strongest-observation -> emit loop shared by every
    algorithm-asset emitter (TLS groups and cipher suites; SSH KEX / host-key / cipher /
    MAC). ``select`` picks the asset name from one Evidence, or None to skip it;
    ``algorithm_properties`` maps a name to its CycloneDX ``algorithmProperties`` (or
    None). Each component records the strongest observation seen (`qureddy:observation`)
    so a consumer can tell a negotiated asset from one merely offered or seen on a
    control probe (#150). Returns name -> bom-ref for callers that cross-reference the
    assets (e.g. protocol cipher-suite edges).
    """
    strongest: dict[str, ObservationType] = {}
    for evidence in result.evidence:
        if evidence.observation_type not in POSITIVE_OBSERVATIONS:
            continue
        name = select(evidence)
        if not name:
            continue
        seen = strongest.get(name)
        if seen is None or OBSERVATION_RANK[evidence.observation_type] > OBSERVATION_RANK[seen]:
            strongest[name] = evidence.observation_type
    refs: dict[str, str] = {}
    for name in sorted(strongest):
        ref = algorithm_ref(name)
        properties = [Property(name="qureddy:observation", value=strongest[name].value)]
        if extra_properties is not None:
            properties.extend(extra_properties(name))
        add_algorithm_component(
            bom,
            name=name,
            ref=ref,
            algorithm_properties=algorithm_properties(name),
            provides_edges=provides_edges,
            properties=properties,
        )
        refs[name] = ref
    return refs


def add_algorithm_component(
    bom: Bom,
    *,
    name: str,
    ref: str,
    algorithm_properties: AlgorithmProperties | None,
    provides_edges: dict[str, list[str]],
    properties: Sequence[Property] = (),
) -> BomRef:
    """Emit one ALGORITHM cryptographic-asset component plus its endpoint provides edge.

    The single place that constructs an algorithm crypto-asset, shared by the evidence-driven
    asset loop above and the certificate-derived single-shot emitters (CA signature algorithm,
    subject public key) so none of them reimplement the component shape (#313). Returns the
    component's BomRef for callers that reference it (e.g. certificateProperties refs).

    Idempotent by bom-ref (#343): if a component with this ref already exists, reuse it rather
    than adding a second. A fully-PQ cert whose signature and subject key are the same
    parameter set (ML-DSA-87 sig + ML-DSA-87 key) resolves both refs to one asset; adding two
    Components with the same bom-ref made cyclonedx rename one to a random ref at
    serialization, orphaning a component and breaking --deterministic.
    """
    if any(existing.bom_ref.value == ref for existing in bom.components):
        return BomRef(value=ref)
    bom.components.add(
        Component(
            name=name,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=ref,
            crypto_properties=CryptoProperties(
                asset_type=CryptoAssetType.ALGORITHM,
                algorithm_properties=algorithm_properties,
            ),
            properties=list(properties),
        )
    )
    add_provides_edge(provides_edges, ref)
    return BomRef(value=ref)
