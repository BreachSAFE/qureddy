# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Canonical finding-type identifiers shared by scanners and output adapters."""

from __future__ import annotations

FINDING_TYPE_PQ_SIGNATURE = "tls.cert.pq_signature"
FINDING_TYPE_CLASSICAL_SIGNATURE = "tls.cert.classical_signature"
FINDING_TYPE_LEGACY_PROTOCOL_OFFERED = "tls.legacy.protocol_offered"
FINDING_TYPE_CLASSICAL_PROTOCOL = "tls.kex.classical_protocol"
