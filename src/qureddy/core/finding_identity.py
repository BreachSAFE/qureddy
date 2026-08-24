# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Stable semantic identity for findings across repeated scans."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from qureddy.core.models import Finding, ScanTarget


def finding_hash(target: ScanTarget, finding: Finding) -> str:
    """Hash endpoint and structured finding facts, excluding run-specific data."""
    identity = {
        "scheme": target.scheme,
        "host": target.host.casefold(),
        "port": target.port,
        "sni": target.sni.casefold() if target.sni else None,
        "rule_id": finding.rule_id,
        "protocol_version": finding.protocol_version,
        "algorithm": finding.algorithm,
        "negotiated_group": finding.negotiated_group,
        "primitive": finding.primitive,
        "parameter_set_identifier": finding.parameter_set_identifier,
        "key_size": finding.key_size,
        "oid": finding.oid,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
