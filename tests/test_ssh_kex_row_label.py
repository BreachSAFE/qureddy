# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The scan-details key_exchange row must not label classical SSH KEX as PQ (#534).

``_style_ssh_kex`` printed the ``PQ hybrid`` prefix for any negotiated group,
never calling the classifier, so a classical-only endpoint (curve25519-sha256)
was labelled ``PQ hybrid`` in contradiction to the verdict rows above it.
"""

from __future__ import annotations

from types import SimpleNamespace

from qureddy.output.console._tables import _style_ssh_kex


def _result(*groups: str) -> SimpleNamespace:
    evidence = [SimpleNamespace(evidence_type="ssh.kex", negotiated_group=g) for g in groups]
    return SimpleNamespace(evidence=evidence)


def test_classical_kex_has_no_pq_prefix() -> None:
    out = _style_ssh_kex(_result("curve25519-sha256")).plain
    assert "PQ hybrid" not in out
    assert "curve25519-sha256" in out


def test_hybrid_kex_keeps_pq_prefix() -> None:
    out = _style_ssh_kex(_result("mlkem768x25519-sha256")).plain
    assert out.startswith("PQ hybrid ")
    assert "mlkem768x25519-sha256" in out


def test_no_ssh_kex_evidence_is_classical_only() -> None:
    assert _style_ssh_kex(SimpleNamespace(evidence=[])).plain == "classical only"
