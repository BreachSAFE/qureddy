# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared crypto-asset emitter core for the CBOM (#288).

One collect -> dedup-by-strongest-observation -> emit loop that every algorithm-asset
emitter (TLS groups and cipher suites; SSH KEX / host-key / cipher / MAC) calls, so TLS
and SSH emit assets through identical machinery. Protocol-specific classification
(name -> algorithmProperties) and evidence selection are supplied by the caller.
"""

from __future__ import annotations

from collections.abc import Callable
from types import MappingProxyType
from typing import TYPE_CHECKING

from cyclonedx.model import Property
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import AlgorithmProperties, CryptoAssetType, CryptoProperties

from qureddy.core.models import ObservationType

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import Evidence, ScanResult

ENDPOINT_REF = "endpoint"

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
        ref = f"crypto/algorithm/{name.lower()}"
        bom.components.add(
            Component(
                name=name,
                type=ComponentType.CRYPTOGRAPHIC_ASSET,
                bom_ref=ref,
                crypto_properties=CryptoProperties(
                    asset_type=CryptoAssetType.ALGORITHM,
                    algorithm_properties=algorithm_properties(name),
                ),
                properties=[Property(name="qureddy:observation", value=strongest[name].value)],
            )
        )
        refs[name] = ref
        provides_edges.setdefault(ENDPOINT_REF, []).append(ref)
    return refs
