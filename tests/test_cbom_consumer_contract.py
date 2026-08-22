# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Drift gate: the CBOM must keep providing what downstream consumers read.

QuReddy's CBOM is consumed by breachsafe-ux (the wizard's `qureddy.yaml` descriptor)
and breachsafe-mint-oscal (its `adapters/cbom.py` -> OSCAL POA&M). A CBOM reshape like
0.2.23/#287 is only safe because those consumers read a *stable* surface. This test
renders a real CBOM and fails if any field in the consumer contract
(fixtures/cbom_consumer_contract.yaml) is missing, naming the consumer that would break —
so a future change can't silently drop it. Removing a requirement means updating that
consumer (and the fixture) deliberately, together.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import yaml

from qureddy.output.cbom import render_cbom
from tests.test_output import _build_result

_CONTRACT = Path(__file__).parent / "fixtures" / "cbom_consumer_contract.yaml"


def _render_cbom() -> dict[str, Any]:
    stream = io.StringIO()
    render_cbom(_build_result(), stream)
    return json.loads(stream.getvalue())


def _resolve(obj: Any, dotted: str) -> Any:
    for key in dotted.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def test_cbom_meets_downstream_consumer_contract() -> None:
    contract = yaml.safe_load(_CONTRACT.read_text(encoding="utf-8"))
    cbom = _render_cbom()
    property_names = {prop["name"] for prop in cbom["metadata"]["properties"]}
    crypto_components = [c for c in cbom["components"] if c.get("type") == "cryptographic-asset"]

    for consumer in contract["consumers"]:
        who = consumer["name"]
        for field, expected in consumer.get("document_fields", {}).items():
            assert cbom.get(field) == expected, (
                f"{who} requires document field {field!r}=={expected!r}, got {cbom.get(field)!r}"
            )
        for name in consumer.get("metadata_properties", []):
            assert name in property_names, (
                f"{who} reads metadata property {name!r}, which is missing from the CBOM"
            )
        for path in consumer.get("every_crypto_component_has", []):
            for component in crypto_components:
                assert _resolve(component, path) is not None, (
                    f"{who} requires {path} on every crypto component; "
                    f"missing on {component.get('name')!r}"
                )
        one = consumer.get("at_least_one_component_with")
        if one:
            assert any(_resolve(c, one) is not None for c in crypto_components), (
                f"{who} requires at least one component with {one}; none found"
            )
