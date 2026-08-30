# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""HNDL exposure must not over-claim on a pure-PQ group with a classical downgrade (#530).

``_hndl_exposure`` classified a pure-PQ key exchange as ``PROTECTED``
unconditionally, ignoring an observed classical downgrade path. The hybrid branch
one line above already demotes to ``PROTECTED_DEFEASIBLE`` when a classical
alternative is present; the pure-PQ branch must mirror it. Over-claiming
protection is the dangerous direction on the platform's headline HNDL verdict.
"""

from __future__ import annotations

from qureddy.scanners.common.posture import HndlExposure, _hndl_exposure


def test_pure_pq_with_classical_downgrade_is_defeasible() -> None:
    # pure-PQ group AND a live classical fallback -> not fully protected.
    got = _hndl_exposure(classical=True, hybrid=False, pure_pq=True, not_testable=False)
    assert got is HndlExposure.PROTECTED_DEFEASIBLE


def test_pure_pq_without_downgrade_stays_protected() -> None:
    got = _hndl_exposure(classical=False, hybrid=False, pure_pq=True, not_testable=False)
    assert got is HndlExposure.PROTECTED


def test_hybrid_branch_unchanged() -> None:
    # regression guard: the hybrid branch already behaved correctly.
    assert (
        _hndl_exposure(classical=True, hybrid=True, pure_pq=False, not_testable=False)
        is HndlExposure.PROTECTED_DEFEASIBLE
    )
    assert (
        _hndl_exposure(classical=False, hybrid=True, pure_pq=False, not_testable=False)
        is HndlExposure.PROTECTED
    )
