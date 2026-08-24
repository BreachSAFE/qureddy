# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the protocol-neutral scanner seam."""

from __future__ import annotations

from qureddy.core.contracts import Scanner
from qureddy.scanners.ssh.scanner import SSHScanner
from qureddy.scanners.tls.scanner import TLSScanner


def test_protocol_specific_scanners_share_the_contract() -> None:
    assert isinstance(TLSScanner(), Scanner)
    assert isinstance(SSHScanner(), Scanner)
    assert TLSScanner.scanner_name == "tls"
    assert SSHScanner.scanner_name == "ssh"


def test_contract_preserves_canonical_result_type() -> None:
    assert Scanner.scan.__annotations__["return"] == "ScanResult"


def test_scanner_subject_is_the_existing_target_model() -> None:
    assert TLSScanner.scan.__annotations__["target"] == "ScanTarget"
