# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The ``qureddy scan wallet`` command body."""

from __future__ import annotations

from typing import Annotated

import typer

from qureddy._branding import PROJECT_URL
from qureddy.cli._errors import EXIT_OK, EXIT_USAGE, _fail
from qureddy.cli._execute import _execute_scan
from qureddy.cli._help import _NO_WRAP_CONTEXT_SETTINGS, _colorize_help_text
from qureddy.cli._options import (
    FormatOpt,
    OutputDirOpt,
    VerboseOpt,
)
from qureddy.cli._render import _prepare_output_dir, _render
from qureddy.cli.main import scan_app
from qureddy.core.logging import start_run_logging
from qureddy.core.models import OutputFormat, ScanTarget
from qureddy.scanners.wallet import address as btc_address
from qureddy.scanners.wallet import ethereum, indexer
from qureddy.scanners.wallet.scanner import WalletScanner

_SCAN_WALLET_EPILOG = _colorize_help_text(f"""\
EXAMPLES:

\b
qureddy scan wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
qureddy scan wallet bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0
qureddy scan wallet 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --format cbom
qureddy scan wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --output-dir ./run

WHAT IS MEASURED:

\b
Bitcoin and Ethereum both sign with secp256k1, which meets no NIST post-quantum
category, so every account reports level 0. That value is constant across the
chain. What varies, and what this scan measures, is whether the public key has
been published on chain, since publication is the input Shor's algorithm needs.

\b
A second finding class is separate in kind: a repeated ECDSA nonce yields the
private key by algebra from public data today, with no quantum computer. That
reports derivability and makes no claim that funds remain.

TRUST BOUNDARY:

\b
The endpoint contacted is a chain indexer or RPC node, named in the target
locator. The account examined is the subject. A finding says which lane produced
it and the expression the value came from. An Ethereum exposure conclusion is
inferred, because that lane reads account state and never key material. Coverage
is one indexer page, which every run states.

\b
QUREDDY_ESPLORA_URL and QUREDDY_ETH_RPC each replace the public defaults, so an
internal node keeps the queried account inside your boundary.

OUTPUT:

\b
--format         rich | json | cbom | jsonl (repeat to override; last wins).
--output-dir     Write all four projections into one run directory.

EXIT CODES:

\b
0   scan succeeded
2   chain lookup failed (indexer or RPC unreachable)
4   usage / configuration error, including an address that fails its checksum

SEE ALSO: {PROJECT_URL}
""")

WalletAddressArg = Annotated[
    str,
    typer.Argument(
        help="Wallet address: bc1..., 1..., 3... for Bitcoin, or 0x... for Ethereum.",
    ),
]
WalletChainOpt = Annotated[
    str | None,
    typer.Option(
        "--type",
        help="Chain to scan: bitcoin or ethereum. Detected from the address when unset.",
        case_sensitive=False,
    ),
]

_BITCOIN = "bitcoin"
_ETHEREUM = "ethereum"
_SCHEME_BY_CHAIN = {_BITCOIN: "btc", _ETHEREUM: "eth"}
_DEFAULT_PORT = 443
_TIMEOUT_SECONDS = 12


def _detect_chain(address: str) -> str:
    """Pick the chain from the address form. An explicit --type overrides this."""
    return _ETHEREUM if (address or "").strip()[:2].lower() == "0x" else _BITCOIN


def _endpoint(chain: str) -> tuple[str, int]:
    """Host and port of the primary endpoint for a chain, from its configured base."""
    import urllib.parse

    bases = ethereum.rpcs() if chain == _ETHEREUM else indexer.bases()
    parsed = urllib.parse.urlsplit(bases[0])
    port = parsed.port or (_DEFAULT_PORT if parsed.scheme == "https" else 80)
    return parsed.hostname or "", port


def _parse_wallet_target(address: str, chain: str | None) -> ScanTarget:
    """Validate the address offline and build the target it belongs to."""
    subject = (address or "").strip()
    if not subject:
        _fail("a wallet address is required", EXIT_USAGE)
    selected = (chain or _detect_chain(subject)).lower()
    if selected not in _SCHEME_BY_CHAIN:
        _fail(f"--type must be one of {sorted(_SCHEME_BY_CHAIN)}: got {selected!r}", EXIT_USAGE)

    # Reject a malformed address here, so a scan never runs against a string that
    # names no account and reports "not tested" for a reason the caller can fix.
    if selected == _ETHEREUM:
        decoded_eth = ethereum.decode(subject)
        if decoded_eth.error:
            _fail(decoded_eth.error, EXIT_USAGE)
        subject = decoded_eth.address
    else:
        decoded_btc = btc_address.decode(subject)
        if decoded_btc.error:
            _fail(decoded_btc.error, EXIT_USAGE)

    scheme = _SCHEME_BY_CHAIN[selected]
    host, port = _endpoint(selected)
    if not host:
        _fail(f"no endpoint is configured for {selected}", EXIT_USAGE)
    return ScanTarget(
        original_input=address,
        host=host,
        port=port,
        sni=None,
        scheme=scheme,
        subject=subject,
        locator=f"{scheme}://{host}:{port}",
    )


@scan_app.command("wallet", epilog=_SCAN_WALLET_EPILOG, context_settings=_NO_WRAP_CONTEXT_SETTINGS)
def scan_wallet_cmd(
    address: WalletAddressArg,
    chain: WalletChainOpt = None,
    fmt: FormatOpt = OutputFormat.RICH,
    output_dir: OutputDirOpt = None,
    verbose: VerboseOpt = 0,
) -> None:
    """Scan a cryptocurrency wallet account for published key material."""
    machine_format = output_dir is not None or fmt is not OutputFormat.RICH
    start_run_logging(
        verbosity=verbose, json_logs=False, quiet=machine_format and verbose == 0, log=None
    )
    scan_target = _parse_wallet_target(address, chain)
    _prepare_output_dir(output_dir, None)
    result, exit_code = _execute_scan(
        WalletScanner(), scan_target, _TIMEOUT_SECONDS, machine_format=machine_format
    )
    _render(
        result,
        fmt,
        verbose,
        reproducible=False,
        compact=False,
        min_severity=None,
        stream=None,
        output_dir=output_dir,
    )
    if exit_code != EXIT_OK:
        raise typer.Exit(code=exit_code)
