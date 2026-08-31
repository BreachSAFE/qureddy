#!/usr/bin/env python3
"""Add the RFC 8247 requirement axis.

IANA status and RFC 8247 requirement are INDEPENDENT: ENCR_NULL is
IANA-current and RFC 8247 MUST NOT; ENCR_3DES is IANA-current and RFC 8247
MAY. Conflating them manufactures findings.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RFC = Path("/Users/paul/claude/breachsafe-standards/standards/rfc/rfc8247/rfc8247.txt")
ROW = re.compile(
    r"^\s*\|\s*([A-Z][A-Z0-9_]+)\s*\|\s*(MUST NOT|SHOULD NOT|MUST-?|SHOULD\+?|SHOULD|MAY|MUST)\s*\|"
)


def main() -> int:
    """Generate the catalog and write it to the given path."""
    lines = RFC.read_text(encoding="utf-8").split(
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
    doc = json.loads(Path(sys.argv[1]).read_text())
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
        "rows_parsed": len(reqs),
        "entries_matched": hit,
        "entries_unmatched": miss,
    }
    Path(sys.argv[1]).write_text(json.dumps(doc, indent=2) + "\n")
    print(f"  parsed {len(reqs)} RFC 8247 rows; matched {hit} entries")
    for n in ("ENCR_NULL", "ENCR_3DES", "ENCR_DES", "PRF_HMAC_MD5"):
        r = reqs.get(n)
        print(
            f"    {n:20} {r['requirement'] if r else 'not in tables':10} {('rfc8247:' + str(r['line'])) if r else ''}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
