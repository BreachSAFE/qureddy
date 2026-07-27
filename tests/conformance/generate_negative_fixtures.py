#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regenerate synthetic-negative fixtures from a known-valid positive CBOM."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
BASE = HERE / "fixtures" / "positive" / "p2-classical-tls.cbom.json"
OUTPUT = HERE / "fixtures" / "negative"


def _wrong_version(payload: dict[str, Any]) -> None:
    payload["specVersion"] = "1.6"


def _duplicate_ref(payload: dict[str, Any]) -> None:
    payload["components"].append(deepcopy(payload["components"][0]))


def _dangling_ref(payload: dict[str, Any]) -> None:
    endpoint = next(item for item in payload["dependencies"] if item["ref"] == "endpoint")
    endpoint["provides"].append("crypto/algorithm/missing")


def _invalid_asset_type(payload: dict[str, Any]) -> None:
    payload["components"][0]["cryptoProperties"]["assetType"] = "quantum-magic"


def _malformed_date(payload: dict[str, Any]) -> None:
    payload["metadata"]["timestamp"] = "27-07-2026 01:45"


def _undeclared_field(payload: dict[str, Any]) -> None:
    payload["qureddyVerdict"] = "ready"


def _secret_material(payload: dict[str, Any]) -> None:
    payload["metadata"]["properties"].append(
        {
            "name": "note",
            "value": "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-TEST-ONLY\n-----END PRIVATE KEY-----",
        }
    )


MUTATIONS: dict[str, tuple[Callable[[dict[str, Any]], None], str]] = {
    "n1-wrong-specversion": (_wrong_version, "specVersion changed to 1.6"),
    "n2-duplicate-bomref": (_duplicate_ref, "first component duplicated"),
    "n3-dangling-ref": (_dangling_ref, "endpoint provides a nonexistent component"),
    "n4-invalid-asset-type": (_invalid_asset_type, "assetType changed to quantum-magic"),
    "n5-malformed-date": (_malformed_date, "metadata.timestamp made non-RFC3339"),
    "n6-undeclared-top-level": (_undeclared_field, "undeclared qureddyVerdict field added"),
    "n7-secret-material": (_secret_material, "synthetic private-key marker added"),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    """Write all negative fixtures and their provenance sidecars."""
    base = json.loads(BASE.read_text(encoding="utf-8"))
    base_digest = _sha256(BASE)
    for name, (mutation, description) in MUTATIONS.items():
        payload = deepcopy(base)
        mutation(payload)
        fixture = OUTPUT / f"{name}.cbom.json"
        fixture.write_text(f"{json.dumps(payload, indent=2)}\n", encoding="utf-8")
        provenance = OUTPUT / f"{name}.provenance.txt"
        provenance.write_text(
            "\n".join(
                (
                    f"fixture: {name}",
                    "classification: synthetic-negative",
                    "not_network_evidence: true",
                    f"derived_from: {BASE.relative_to(HERE)}",
                    f"base_sha256: {base_digest}",
                    f"mutation: {description}",
                    f"sha256: {_sha256(fixture)}",
                    "",
                )
            ),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
