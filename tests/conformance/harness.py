# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Independent validation of final CycloneDX 1.7 byte streams."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import rfc3339_validator
from jsonschema import Draft7Validator, FormatChecker
from jsonschema.exceptions import FormatError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

ROOT = Path(__file__).resolve().parents[2]
CONFORMANCE_DIR = ROOT / "tests" / "conformance"
SCHEMA_DIR = CONFORMANCE_DIR / "schemas" / "cyclonedx-1.7.1"
FIXTURE_DIR = CONFORMANCE_DIR / "fixtures"
MANIFEST_PATH = CONFORMANCE_DIR / "manifest.json"
TOOL_MANIFEST_PATH = CONFORMANCE_DIR / "cyclonedx-cli-v0.33.1.json"

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_SECRET_FIELD = re.compile(
    r"^(?:access[_ -]?token|refresh[_ -]?token|api[_ -]?key|session[_ -]?key|"
    r"password|credential|secret)$",
    re.IGNORECASE,
)


def sha256(path: Path) -> str:
    """Return the lowercase SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest() -> dict[str, Any]:
    """Load the fixture and schema contract."""
    return cast("dict[str, Any]", json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))


def verify_schema_assets() -> None:
    """Fail closed if any vendored official schema byte changes."""
    expected = load_manifest()["schemas"]["files"]
    actual = {name: sha256(SCHEMA_DIR / name) for name in expected}
    if actual != expected:
        msg = f"vendored CycloneDX schema digest mismatch: {actual!r}"
        raise ValueError(msg)


def official_validator() -> Draft7Validator:
    """Build an offline validator from the pinned official schema set."""
    verify_schema_assets()
    registry = Registry()
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource.from_contents(document, default_specification=DRAFT7)
        registry = registry.with_resource(document.get("$id", path.name), resource)
        registry = registry.with_resource(path.name, resource)
    schema = json.loads((SCHEMA_DIR / "bom-1.7.schema.json").read_text(encoding="utf-8"))
    checker = FormatChecker()
    try:
        checker.check("not-an-rfc3339-date", "date-time")
    except FormatError:
        pass
    else:
        msg = "RFC3339 date-time validation is unavailable"
        raise RuntimeError(msg)
    if not callable(rfc3339_validator.validate_rfc3339):
        msg = "rfc3339-validator is unavailable"
        raise RuntimeError(msg)
    return Draft7Validator(schema, registry=registry, format_checker=checker)


def official_errors(payload: dict[str, Any]) -> list[str]:
    """Return stable official-schema errors for a decoded CBOM."""
    errors = official_validator().iter_errors(payload)
    return sorted(error.message for error in errors)


def semantic_errors(payload: dict[str, Any]) -> list[str]:
    """Apply BreachSAFE checks for constraints outside schema validation."""
    errors: list[str] = []
    if payload.get("specVersion") != "1.7":
        errors.append("specVersion must be exactly 1.7")
    declared = _declared_refs(payload)
    duplicates = sorted(ref for ref in set(declared) if declared.count(ref) > 1)
    if duplicates:
        errors.append(f"duplicate bom-ref values: {', '.join(duplicates)}")
    dangling = sorted(_referenced_refs(payload) - set(declared))
    if dangling:
        errors.append(f"dangling references: {', '.join(dangling)}")
    if _contains_secret_like_material(payload):
        errors.append("secret-like material is prohibited")
    return errors


def independent_cli_errors(binary: Path, artifact: Path) -> list[str]:
    """Validate one artifact using the pinned independent CycloneDX CLI."""
    completed = subprocess.run(  # noqa: S603 - binary digest is verified before use.
        [
            str(binary),
            "validate",
            "--input-file",
            str(artifact),
            "--input-format",
            "json",
            "--input-version",
            "v1_7",
            "--fail-on-errors",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode == 0:
        return []
    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    return [output.strip() or f"cyclonedx-cli exited {completed.returncode}"]


def verify_independent_cli(binary: Path, asset_key: str) -> None:
    """Verify validator version and bytes against the pinned release manifest."""
    manifest = json.loads(TOOL_MANIFEST_PATH.read_text(encoding="utf-8"))
    asset = manifest["assets"].get(asset_key)
    if asset is None:
        msg = f"unsupported cyclonedx-cli asset key: {asset_key}"
        raise ValueError(msg)
    actual = sha256(binary)
    if actual != asset["sha256"]:
        msg = f"cyclonedx-cli digest mismatch: expected {asset['sha256']}, got {actual}"
        raise ValueError(msg)
    completed = subprocess.run(  # noqa: S603 - binary digest is verified above.
        [str(binary), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if manifest["version"] not in f"{completed.stdout}\n{completed.stderr}":
        msg = f"unexpected cyclonedx-cli version output: {completed.stdout!r}"
        raise ValueError(msg)


def normalized_volatile_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """Remove the two CycloneDX document identity fields before comparison."""
    normalized = deepcopy(payload)
    normalized.pop("serialNumber", None)
    metadata = normalized.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)
    return normalized


def _declared_refs(payload: dict[str, Any]) -> list[str]:
    locations: list[object] = [payload.get("metadata", {}).get("component", {})]
    locations.extend(payload.get("components", []))
    locations.extend(payload.get("services", []))
    locations.extend(payload.get("metadata", {}).get("tools", {}).get("components", []))
    return [
        value["bom-ref"]
        for value in locations
        if isinstance(value, dict) and isinstance(value.get("bom-ref"), str)
    ]


def _referenced_refs(payload: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for dependency in payload.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue
        for key in ("ref", "dependsOn", "provides"):
            value = dependency.get(key, [])
            refs.update([value] if isinstance(value, str) else value)
    for component in payload.get("components", []):
        crypto = component.get("cryptoProperties", {}) if isinstance(component, dict) else {}
        protocol = crypto.get("protocolProperties", {})
        for suite in protocol.get("cipherSuites", []):
            refs.update(ref for ref in suite.get("algorithms", []) if isinstance(ref, str))
        signature_ref = crypto.get("certificateProperties", {}).get("signatureAlgorithmRef")
        if isinstance(signature_ref, str):
            refs.add(signature_ref)
    return refs


def _contains_secret_like_material(value: object) -> bool:
    if isinstance(value, dict):
        if any(
            _SECRET_FIELD.fullmatch(str(key)) and nested not in (None, "", [], {})
            for key, nested in value.items()
        ):
            return True
        property_name = value.get("name")
        if (
            isinstance(property_name, str)
            and _SECRET_FIELD.fullmatch(property_name)
            and value.get("value") not in (None, "", [], {})
        ):
            return True
        return any(_contains_secret_like_material(nested) for nested in value.values())
    if isinstance(value, list):
        return any(_contains_secret_like_material(item) for item in value)
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in _SECRET_PATTERNS)
    return False
