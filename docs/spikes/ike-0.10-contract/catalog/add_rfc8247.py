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


def main() -> int:
    """Generate the catalog and write it to the given path."""
    args = parse_args()
    verify_rfc(args.rfc_path)
    lines = args.rfc_path.read_text(encoding="utf-8").split(
        "\n"
    )  # NOT splitlines(): \x0c would shift every citation
    reqs: dict[str, dict] = {}
    for i, line in enumerate(lines, 1):
        m = ROW.match(line)
        if not m:
            continue
        name, level = m.group(1), m.group(2).strip()
        # first occurrence wins; later tables restate for AH/ESP context
        reqs.setdefault(name, {"requirement": level, "line": i})
    doc = json.loads(args.catalog.read_text(encoding="utf-8"))
    hit = miss = 0
    for e in doc["entries"]:
        r = reqs.get(e["name"])
        if r and e["ike_version"] == "2":
            e["rfc8247_requirement"] = r["requirement"]
            e["rfc8247_citation"] = f"rfc8247/rfc8247.txt:{r['line']}"
            hit += 1
        else:
            e["rfc8247_requirement"] = None
            e["rfc8247_citation"] = None
            miss += 1
    doc["rfc8247_axis"] = {
        "note": "IANA status and RFC 8247 requirement are independent axes",
        "source_url": RFC_URL,
        "sha256": RFC_SHA256,
        "rows_parsed": len(reqs),
        "entries_matched": hit,
        "entries_unmatched": miss,
    }
    args.catalog.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"  parsed {len(reqs)} RFC 8247 rows; matched {hit} entries")
    for n in ("ENCR_NULL", "ENCR_3DES", "ENCR_DES", "PRF_HMAC_MD5"):
        r = reqs.get(n)
        print(
            f"    {n:20} {r['requirement'] if r else 'not in tables':10} {('rfc8247:' + str(r['line'])) if r else ''}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
