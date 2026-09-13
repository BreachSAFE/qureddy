# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The documented chain list against the one the code enforces.

Litecoin shipped and every document kept describing two chains, which is
`breachsafe-ai-slop-review` item 1: a second representation of a fact that no
longer matches its source. `SUPPORTED_SCHEMES` is that source, so these read it
rather than pinning a list of their own.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import pytest

from qureddy.cli.wallet import _SCAN_WALLET_EPILOG, _SCHEME_BY_CHAIN, WalletAddressArg
from qureddy.core.models import SUBJECT_SCHEMES
from qureddy.scanners.wallet.indexer import DEFAULT_BASES_BY_CHAIN
from qureddy.scanners.wallet.profiles import PROFILES

_DOCS = Path(__file__).resolve().parents[1] / "docs" / "architecture"
_ADR = _DOCS / "wallet-scanner-adr.md"
_VIEWS = _DOCS / "wallet-scanner-views.md"


def _chains() -> set[str]:
    """Chain names the CLI accepts, keyed to the schemes the core enforces."""
    return set(_SCHEME_BY_CHAIN)


def test_the_cli_offers_exactly_the_subject_schemes_core_allows() -> None:
    """A chain the CLI names and the core rejects would fail only at run time."""
    assert set(_SCHEME_BY_CHAIN.values()) == set(SUBJECT_SCHEMES)


@pytest.mark.parametrize("chain", sorted(_SCHEME_BY_CHAIN))
def test_every_supported_chain_is_named_in_the_help(chain: str) -> None:
    """A capability no help text admits to reads as absent."""
    option = WalletAddressArg.__metadata__[0]
    text = f"{_SCAN_WALLET_EPILOG}\n{option.help}".lower()

    assert chain in text, f"{chain} is missing from the wallet help"


@pytest.mark.parametrize("chain", sorted(_SCHEME_BY_CHAIN))
def test_every_supported_chain_has_a_grounded_profile(chain: str) -> None:
    """C6: a chain with no grounded address cannot be demonstrated or tested."""
    assert any(profile.chain == chain for profile in PROFILES), chain


@pytest.mark.parametrize("chain", sorted(_SCHEME_BY_CHAIN))
def test_every_supported_chain_appears_in_the_adr(chain: str) -> None:
    assert chain in _ADR.read_text(encoding="utf-8").lower(), chain


@pytest.mark.parametrize("scheme", sorted(SUBJECT_SCHEMES))
def test_the_adr_scheme_set_lists_every_subject_scheme(scheme: str) -> None:
    """The ADR writes the scheme set out; it has to match what models.py holds."""
    line = next(
        row for row in _ADR.read_text(encoding="utf-8").splitlines() if "scheme in {" in row
    )

    assert scheme in line, f"{scheme} is missing from the ADR scheme set: {line.strip()}"


def test_the_views_context_diagram_names_every_default_indexer() -> None:
    """A diagram omitting a live endpoint understates where data comes from."""
    text = _VIEWS.read_text(encoding="utf-8")
    for bases in DEFAULT_BASES_BY_CHAIN.values():
        for base in bases:
            host = urlsplit(base).hostname or ""
            assert host in text, f"{host} is missing from the views diagrams"
