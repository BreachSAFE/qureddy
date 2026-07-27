#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Replays the minimized classical example.com capture without network access.
set -eu
fixture_root="$(cd "$(dirname "$0")/../.." && pwd)"
case "$1" in
    version)
        echo "OpenSSL 3.5.6 7 Apr 2026"
        ;;
    list)
        echo "TLS 1.3 supported groups:"
        echo "  X25519MLKEM768:x25519:secp256r1"
        ;;
    s_client)
        grep -v '^#' "$fixture_root/fixtures/openssl/brief_classical_example_com.txt"
        ;;
    *)
        echo "classical replay: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
