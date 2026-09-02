#!/usr/bin/env python3
"""Add the RFC 8247 requirement axis.

IANA status and RFC 8247 requirement are INDEPENDENT: ENCR_NULL is
IANA-current and RFC 8247 MUST NOT; ENCR_3DES is IANA-current and RFC 8247
MAY. Conflating them manufactures findings.
"""

from __future__ import annotations

import hashlib
import json
import re
from argparse import ArgumentParser, Namespace
from pathlib import Path

RFC_SHA256 = "e1e6a86cfddcb2ebbe39ba1c2cf5516b8cb5f39fd0d53dea468a522a3b7a7250"
RFC_URL = "https://www.rfc-editor.org/rfc/rfc8247.txt"
ROW = re.compile(
    r"^\s*\|\s*([A-Z][A-Z0-9_]+)\s*\|\s*(MUST NOT|SHOULD NOT|MUST-?|SHOULD\+?|SHOULD|MAY|MUST)\s*\|"
)


def parse_args() -> Namespace:
    """Parse explicit, portable input paths."""
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--rfc-path", required=True, type=Path, help="pinned RFC 8247 text")
    parser.add_argument("--catalog", required=True, type=Path, help="catalog JSON to update")
    return parser.parse_args()


def verify_rfc(path: Path) -> None:
    """Fail closed unless RFC 8247 matches the pinned source digest."""
    if not path.is_file():
        raise SystemExit(f"required input does not exist: {path}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != RFC_SHA256:
        raise SystemExit(f"input digest mismatch for {path}: expected {RFC_SHA256}, got {actual}")


def parse_requirements(text: str) -> dict[str, dict]:
    """Parse the first requirement for each RFC table algorithm."""
    lines = text.split("\n")  # NOT splitlines(): \x0c would shift every citation
    requirements: dict[str, dict] = {}
    for line_number, line in enumerate(lines, 1):
        match = ROW.match(line)
        if match:
            name, level = match.group(1), match.group(2).strip()
            # First occurrence wins; later tables restate AH/ESP context.
            requirements.setdefault(name, {"requirement": level, "line": line_number})
    return requirements


def apply_requirements(doc: dict, requirements: dict[str, dict]) -> tuple[int, int]:
    """Add the independent RFC requirement axis to catalog entries."""
    matched = unmatched = 0
    for entry in doc["entries"]:
        requirement = requirements.get(entry["name"])
        if requirement and entry["ike_version"] == "2":
            entry["rfc8247_requirement"] = requirement["requirement"]
            entry["rfc8247_citation"] = f"rfc8247/rfc8247.txt:{requirement['line']}"
            matched += 1
        else:
            entry["rfc8247_requirement"] = None
            entry["rfc8247_citation"] = None
            unmatched += 1
    return matched, unmatched


def main() -> int:
    """Generate the catalog and write it to the given path."""
    args = parse_args()
    verify_rfc(args.rfc_path)
    requirements = parse_requirements(args.rfc_path.read_text(encoding="utf-8"))
    doc = json.loads(args.catalog.read_text(encoding="utf-8"))
    matched, unmatched = apply_requirements(doc, requirements)
    doc["rfc8247_axis"] = {
        "note": "IANA status and RFC 8247 requirement are independent axes",
        "source_url": RFC_URL,
        "sha256": RFC_SHA256,
        "rows_parsed": len(requirements),
        "entries_matched": matched,
        "entries_unmatched": unmatched,
    }
    args.catalog.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"  parsed {len(requirements)} RFC 8247 rows; matched {matched} entries")
    for n in ("ENCR_NULL", "ENCR_3DES", "ENCR_DES", "PRF_HMAC_MD5"):
        r = requirements.get(n)
        print(
            f"    {n:20} {r['requirement'] if r else 'not in tables':10} {('rfc8247:' + str(r['line'])) if r else ''}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
