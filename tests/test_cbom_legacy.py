# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the legacy TLS cipher CBOM emitter + classifier (#303).

The ``classically_weak`` branch cannot be reached by a real scan — OpenSSL 3.5.7 LTS has
3DES/RC4 compiled out and refuses to negotiate them — so it is covered here directly.
"""

from __future__ import annotations

import io
import json

import pytest

from qureddy.core.models import Asset, Evidence, ObservationType
from qureddy.output import cbom_legacy
from qureddy.output.cbom import render_cbom
from qureddy.scanners.tls._legacy_findings import cipher_evidence_from_legacy_result
from qureddy.scanners.tls.legacy_probe import LegacyProtocolResult
from tests.test_output import _build_result


@pytest.mark.parametrize(
    ("name", "bits"),
    [
        ("ECDHE-RSA-AES256-GCM-SHA384", 256),
        ("ECDHE-RSA-AES192-CBC-SHA", 192),
        ("ECDHE-RSA-AES128-SHA", 128),
        ("DES-CBC3-SHA", 112),
        ("ECDHE-RSA-CHACHA20-POLY1305", 256),
        ("RC4-SHA", None),
        ("NULL-MD5", None),
    ],
)
def test_legacy_cipher_bits(name: str, bits: int | None) -> None:
    assert cbom_legacy._legacy_cipher_bits(name) == bits  # noqa: SLF001


@pytest.mark.parametrize(
    ("name", "primitive"),
    [
        ("ECDHE-RSA-AES256-GCM-SHA384", "ae"),
        ("ECDHE-RSA-CHACHA20-POLY1305", "ae"),
        ("RC4-SHA", "stream-cipher"),
        ("DES-CBC3-SHA", "block-cipher"),
        ("ECDHE-RSA-AES128-SHA", "block-cipher"),
    ],
)
def test_legacy_cipher_primitive(name: str, primitive: str) -> None:
    assert cbom_legacy._legacy_cipher_primitive(name).value == primitive  # noqa: SLF001


def test_legacy_cipher_properties_carries_classical_level_never_quantum() -> None:
    props = cbom_legacy._legacy_cipher_properties("ECDHE-RSA-AES256-GCM-SHA384")  # noqa: SLF001
    assert props.primitive.value == "ae"
    assert props.classical_security_level == 256
    assert props.nist_quantum_security_level is None


def test_legacy_verdict_weak_cipher() -> None:
    verdict = {p.name: p.value for p in cbom_legacy._legacy_cipher_verdict("DES-CBC3-SHA")}  # noqa: SLF001
    assert verdict["qureddy:readiness"] == "classically_weak"
    assert verdict["qureddy:severity"] == "high"


def test_legacy_verdict_strong_classical_cipher() -> None:
    verdict = {
        p.name: p.value
        for p in cbom_legacy._legacy_cipher_verdict("ECDHE-RSA-AES256-GCM-SHA384")  # noqa: SLF001
    }
    assert verdict["qureddy:readiness"] == "quantum_vulnerable"
    assert verdict["qureddy:severity"] == "low"


def _asset() -> Asset:
    return Asset(id="asset-x", asset_type="tls.endpoint", locator="h:443", display_name="h:443")


def test_cipher_evidence_offered_emits_one_per_cipher() -> None:
    result = LegacyProtocolResult(
        protocol_flag="-tls1_2",
        protocol_version="TLSv1.2",
        offered=True,
        accepted_ciphers=("AES128-SHA", "DES-CBC3-SHA"),
    )
    evidence = cipher_evidence_from_legacy_result(_asset(), result)
    assert [e.negotiated_group for e in evidence] == ["AES128-SHA", "DES-CBC3-SHA"]
    assert all(e.evidence_type == "tls.legacy.cipher" for e in evidence)


def test_cipher_evidence_not_offered_is_empty() -> None:
    result = LegacyProtocolResult(
        protocol_flag="-tls1_1", protocol_version="TLSv1.1", offered=False, accepted_ciphers=()
    )
    assert cipher_evidence_from_legacy_result(_asset(), result) == []


def test_render_emits_legacy_cipher_components_with_verdict() -> None:
    base = _build_result()
    asset_id = base.assets[0].id
    weak = Evidence(
        id="lc-weak",
        asset_id=asset_id,
        evidence_type="tls.legacy.cipher",
        observation_type=ObservationType.OFFERED,
        source="qureddy.scanners.tls.legacy_probe",
        protocol_version="TLSv1.2",
        negotiated_group="DES-CBC3-SHA",
        notes=("accepted on TLSv1.2",),
    )
    strong = Evidence(
        id="lc-strong",
        asset_id=asset_id,
        evidence_type="tls.legacy.cipher",
        observation_type=ObservationType.OFFERED,
        source="qureddy.scanners.tls.legacy_probe",
        protocol_version="TLSv1.2",
        negotiated_group="AES256-GCM-SHA384",
        notes=("accepted on TLSv1.2",),
    )
    result = base.model_copy(update={"evidence": (*base.evidence, weak, strong)})
    stream = io.StringIO()
    render_cbom(result, stream)
    components = {c["name"]: c for c in json.loads(stream.getvalue())["components"]}

    assert "DES-CBC3-SHA" in components
    assert "AES256-GCM-SHA384" in components
    weak_props = {p["name"]: p["value"] for p in components["DES-CBC3-SHA"]["properties"]}
    assert weak_props["qureddy:readiness"] == "classically_weak"
    assert weak_props["qureddy:severity"] == "high"
    strong_props = {p["name"]: p["value"] for p in components["AES256-GCM-SHA384"]["properties"]}
    assert strong_props["qureddy:readiness"] == "quantum_vulnerable"
