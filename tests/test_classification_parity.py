# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Cross-format regression coverage for cryptographic classification parity."""

from __future__ import annotations

import io
import json

from qureddy.core.algorithm_profile import classify_key_exchange
from qureddy.core.models import Evidence, ObservationType
from qureddy.core.policy import classify_evidence
from qureddy.output.cbom import render_cbom
from qureddy.output.json import render_json
from qureddy.output.jsonl import render_jsonl
from tests._cbom_fixtures import _build_result


def test_key_exchange_classifier_rejects_embedded_known_tokens() -> None:
    """Keep server-controlled names from spoofing a recognized classical group."""
    assert classify_key_exchange("notx25519evil") is None
    assert classify_key_exchange("notcurve25519evil") is None


def test_x25519_classification_matches_json_jsonl_and_cbom() -> None:
    """Project one classified finding identically across every machine format."""
    base = _build_result()
    evidence = Evidence(
        id="evidence-x25519",
        asset_id=base.assets[0].id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        negotiated_group="X25519",
    )
    finding = classify_evidence(base.assets[0], [evidence])[0]
    result = base.model_copy(update={"evidence": (evidence,), "findings": (finding,)})

    json_stream = io.StringIO()
    render_json(result, json_stream)
    json_finding = json.loads(json_stream.getvalue())["findings"][0]

    jsonl_stream = io.StringIO()
    render_jsonl(result, jsonl_stream)
    jsonl_finding = json.loads(jsonl_stream.getvalue().splitlines()[0])
    jsonl_metadata = jsonl_finding["info"]["metadata"]

    cbom_stream = io.StringIO()
    render_cbom(result, cbom_stream, reproducible=True)
    cbom = json.loads(cbom_stream.getvalue())
    cbom_properties = next(
        component["cryptoProperties"]["algorithmProperties"]
        for component in cbom["components"]
        if component["bom-ref"] == "crypto/algorithm/x25519"
    )

    expected = ("key-agree", 0)
    assert (json_finding["primitive"], json_finding["nist_quantum_security_level"]) == expected
    assert (
        jsonl_metadata["primitive"],
        jsonl_metadata["nist_quantum_security_level"],
    ) == expected
    assert (
        cbom_properties["primitive"],
        cbom_properties["nistQuantumSecurityLevel"],
    ) == expected
