# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Golden contracts for normalized Rich, JSON, and CBOM output."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path
from typing import Any

import pytest

from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.output.json import render_json
from tests.test_output import _build_result

GOLDEN_DIR = Path(__file__).parent / "golden"
_GENERATED_BOM_REF = re.compile(r"^BomRef\.[0-9.]+$")


def _normalize_json(text: str) -> str:
    return json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"


def _normalize_cbom_value(value: Any, *, key: str | None = None) -> Any:
    if key == "serialNumber":
        return "<normalized-serial-number>"
    if key == "timestamp":
        return "<normalized-timestamp>"
    if isinstance(value, str) and _GENERATED_BOM_REF.fullmatch(value):
        return "<normalized-generated-bom-ref>"
    if isinstance(value, dict):
        return {
            item_key: _normalize_cbom_value(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_normalize_cbom_value(item) for item in value]
    return value


def _normalize_cbom(text: str) -> str:
    normalized = _normalize_cbom_value(json.loads(text))
    return json.dumps(normalized, indent=2, sort_keys=True) + "\n"


def _normalize_rich(text: str) -> str:
    lines = [line.rstrip() for line in text.splitlines()]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def _actual_outputs() -> dict[str, str]:
    result = _build_result()
    outputs: dict[str, str] = {}
    for name, renderer in (
        ("rich", render_rich),
        ("json", render_json),
        ("cbom", render_cbom),
    ):
        stream = io.StringIO()
        renderer(result, stream)
        outputs[name] = stream.getvalue()
    return {
        "rich": _normalize_rich(outputs["rich"]),
        "json": _normalize_json(outputs["json"]),
        "cbom": _normalize_cbom(outputs["cbom"]),
    }


@pytest.mark.parametrize("output_format", ["rich", "json", "cbom"])
def test_normalized_output_matches_golden(output_format: str) -> None:
    expected = (GOLDEN_DIR / f"{output_format}.golden").read_text(encoding="utf-8")
    assert _actual_outputs()[output_format] == expected
