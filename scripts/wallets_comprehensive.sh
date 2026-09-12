#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Scan every grounded wallet profile on screen, rich format, maximum tracing.
#
# Output goes to the terminal only. Nothing is piped to a file and no
# --output-dir is passed, so what you read is what the run produced. To keep
# the artefacts, run one address with --output-dir separately.
#
# Each address and the claim it carries live in
# src/qureddy/scanners/wallet/profiles.py; the grounding for each is section 12
# of docs/architecture/wallet-scanner-adr.md.

set -uo pipefail

timeout_seconds="${QUREDDY_TIMEOUT:-20}"

printf 'QuReddy: '
uv run --locked qureddy --version
printf 'Esplora base: %s\n' "${QUREDDY_ESPLORA_URL:-<public defaults>}"
printf 'Ethereum RPC: %s\n' "${QUREDDY_ETH_RPC:-<public defaults>}"

overall_status=0

# address<TAB>profile key<TAB>what the run should show.
# The last row is a negative case: a mutated checksum must exit 4 offline,
# before any packet leaves, so a clean run here proves the gate still holds.
scan_case() {
  local address="$1" key="$2" expect="$3"
  printf '\n=== %s · %s ===\n' "${key}" "${address}"
  printf '    expect: %s\n' "${expect}"
  uv run --locked qureddy scan wallet "${address}" --format rich -vvv
  local status=$?
  printf '    exit code: %d\n' "${status}"
  if [[ "${key}" == "negative-bad-checksum" ]]; then
    if (( status != 4 )); then
      printf 'FAIL: expected exit 4 for a bad checksum, got %d\n' "${status}" >&2
      overall_status=1
    fi
  elif (( status != 0 )); then
    printf 'FAIL: %s exited %d\n' "${key}" "${status}" >&2
    overall_status="${status}"
  fi
}

export QUREDDY_TIMEOUT="${timeout_seconds}"

scan_case 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa \
  btc-genesis \
  'P2PK output, public key on chain, p2pk_sibling reads not tested'

scan_case bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0 \
  btc-taproot \
  'v1 witness program is the x-only key itself, so the key is published by the address'

scan_case bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 \
  btc-bip173-example \
  'v0 witness program, key published only once an input spends it'

scan_case 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 \
  eth-delegated-account \
  'eth_getCode returns a 23-byte 0xef0100 delegation indicator'

scan_case 0xdAC17F958D2ee523a2206206994597C13D831ec7 \
  eth-contract \
  'contract account, so no externally owned key exists at this address'

scan_case 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb \
  negative-bad-checksum \
  'base58check fails, exit 4, no network call'

printf '\n=== overall exit %d ===\n' "${overall_status}"
exit "${overall_status}"
