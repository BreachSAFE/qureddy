#!/usr/bin/env python3
"""Generate the versioned IKE algorithm catalog from the PINNED IANA snapshots.

No network. Every row carries its registry file, the registry's own updated
date, the defining xref, and the SHA-256 of the snapshot it came from.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

CORPUS = Path("/Users/paul/claude/breachsafe-standards/standards/rfc/iana-ike")

# role -> (registry file, registry id, ike version, wire location)
SPEC = {
    # IKEv2: transform types 1-5, RFC 7296 section 3.3.2
    ("2", "encryption"): ("ikev2-parameters.xml", "ikev2-parameters-5", "transform_type=1"),
    ("2", "prf"): ("ikev2-parameters.xml", "ikev2-parameters-6", "transform_type=2"),
    ("2", "integrity"): ("ikev2-parameters.xml", "ikev2-parameters-7", "transform_type=3"),
    ("2", "key_exchange"): ("ikev2-parameters.xml", "ikev2-parameters-8", "transform_type=4"),
    ("2", "esn"): ("ikev2-parameters.xml", "ikev2-parameters-9", "transform_type=5"),
    ("2", "transform_type"): (
        "ikev2-parameters.xml",
        "ikev2-parameters-3",
        "transform_type_registry",
    ),
    ("2", "attribute_type"): ("ikev2-parameters.xml", "ikev2-parameters-4", "transform_attribute"),
    ("2", "authentication"): ("ikev2-parameters.xml", "ikev2-parameters-12", "auth_method_payload"),
    ("2", "notify_error"): ("ikev2-parameters.xml", "ikev2-parameters-14", "notify_type"),
    ("2", "notify_status"): ("ikev2-parameters.xml", "ikev2-parameters-16", "notify_type"),
    # IKEv1 Phase 1 / IKE SA attributes live in ipsec-registry.xml
    ("1", "encryption"): ("ipsec-registry.xml", "ipsec-registry-4", "sa_attribute=1"),
    ("1", "hash"): ("ipsec-registry.xml", "ipsec-registry-6", "sa_attribute=2"),
    ("1", "authentication"): ("ipsec-registry.xml", "ipsec-registry-8", "sa_attribute=3"),
    ("1", "key_exchange"): ("ipsec-registry.xml", "ipsec-registry-10", "sa_attribute=4"),
    ("1", "group_type"): ("ipsec-registry.xml", "ipsec-registry-12", "sa_attribute=5"),
    ("1", "life_type"): ("ipsec-registry.xml", "ipsec-registry-14", "sa_attribute=11"),
    ("1", "attribute_type"): ("ipsec-registry.xml", "ipsec-registry-2", "sa_attribute_classes"),
    ("1", "exchange_type"): ("ipsec-registry.xml", "ipsec-registry-17", "isakmp_header_exchange"),
    ("1", "notify_error"): ("ipsec-registry.xml", "ipsec-registry-23", "notify_type"),
}

# 0.10-0.13 scheduled profiles. Everything else is catalog-only.
SCHEDULED = {
    ("2", "key_exchange", 14),
    ("2", "key_exchange", 19),
    ("2", "key_exchange", 31),
    ("2", "encryption", 12),
    ("2", "encryption", 20),
    ("2", "prf", 5),
    ("2", "integrity", 12),
    ("1", "encryption", 7),
    ("1", "hash", 2),
    ("1", "key_exchange", 14),
    ("1", "authentication", 1),
}
NEVER_SCHEDULED = {("2", "key_exchange", 35)}  # ML-KEM-512: catalog-only, permanently not_tested
POST_MVP = {("2", "key_exchange", 36), ("2", "key_exchange", 37)}  # ML-KEM-768/1024 -> 0.14 #555


def sha256(p: Path) -> str:
    """Return the SHA-256 hex digest of a file."""
    return hashlib.sha256(p.read_bytes()).hexdigest()


def updated(text: str) -> str:
    """Extract the registry's own <updated> date."""
    m = re.search(r"<updated>([^<]+)</updated>", text)
    return m.group(1) if m else "unknown"


def xrefs(block: str) -> list[str]:
    """Collect rfc/draft xrefs from one record block, in order."""
    out = []
    for t, d in re.findall(r'<xref type="(rfc|draft)" data="([^"]+)"', block):
        tag = f"{t}:{d}"
        if tag not in out:
            out.append(tag)
    return out


def parse(path: Path, reg_id: str) -> list[dict]:
    """Parse one registry block into value/name/status/xref rows."""
    text = path.read_text(encoding="utf-8")
    m = re.search(rf'<registry id="{re.escape(reg_id)}">.*?</registry>', text, re.S)
    if not m:
        raise SystemExit(f"registry {reg_id} not found in {path.name}")
    rows = []
    for rec in re.findall(r"<record.*?</record>", m.group(0), re.S):
        val = re.search(r"<value>([^<]*)</value>", rec)
        # ikev2-parameters.xml uses <description>; ipsec-registry.xml uses <name>.
        # Matching only one silently drops an entire IKE version.
        des = re.search(r"<description>(.*?)</description>", rec, re.S) or re.search(
            r"<name>(.*?)</name>", rec, re.S
        )
        if not val or not des:
            continue
        v = val.group(1).strip()
        name = re.sub(r"<[^>]+>", "", des.group(1)).strip()
        st = re.search(r"<status>(.*?)</status>", rec, re.S)
        status = re.sub(r"<[^>]+>", "", st.group(1)).strip().split()[0].lower() if st else None
        rows.append({"value": v, "name": name, "status_raw": status, "xrefs": xrefs(rec)})
    return rows


def classify(name: str, status: str | None) -> str:
    """Map a registry name and status to a catalog status token."""
    n = name.lower()
    if status == "deprecated":
        return "deprecated"
    if n in ("unassigned",):
        return "unassigned"
    if "reserved for private use" in n:
        return "private_use"
    if n.startswith("reserved"):
        return "reserved"
    return "current"


def main() -> int:
    """Generate the catalog and write it to the given path."""
    files = {f: (CORPUS / f) for f in {v[0] for v in SPEC.values()}}
    prov = {
        f: {"sha256": sha256(p), "updated": updated(p.read_text(encoding="utf-8"))}
        for f, p in files.items()
    }
    entries, skipped = [], 0
    for (ver, role), (fname, reg_id, wire) in sorted(SPEC.items()):
        for r in parse(files[fname], reg_id):
            v = r["value"]
            if not v.isdigit():  # ranges: Unassigned / Private Use
                skipped += 1
                continue
            wid = int(v)
            key = (ver, role, wid)
            sched = (
                "scheduled_0_10"
                if key in SCHEDULED
                else "post_mvp_0_14_555"
                if key in POST_MVP
                else "catalog_only_never_scheduled"
                if key in NEVER_SCHEDULED
                else "catalog_only"
            )
            entries.append(
                {
                    "ike_version": ver,
                    "role": role,
                    "wire_location": wire,
                    "wire_id": wid,
                    "name": r["name"],
                    "status": classify(r["name"], r["status_raw"]),
                    "citations": r["xrefs"] or None,
                    "registry_file": fname,
                    "registry_updated": prov[fname]["updated"],
                    "registry_sha256": prov[fname]["sha256"],
                    "scheduled_profile": sched,
                }
            )
    entries.sort(key=lambda e: (e["ike_version"], e["role"], e["wire_id"]))
    doc = {
        "schema": "qureddy.ike.algorithm-catalog.v1",
        "catalog_version": "0.10.0-draft1",
        "source": "pinned IANA snapshots; no network fetch",
        "provenance": prov,
        "entry_count": len(entries),
        "range_rows_skipped": skipped,
        "entries": entries,
    }
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "ike-catalog.json")
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {out}: {len(entries)} entries, {skipped} range rows skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
