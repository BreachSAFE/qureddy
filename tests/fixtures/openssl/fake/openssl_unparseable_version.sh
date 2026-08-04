#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Fake openssl that exits 0 but prints version output `_extract_version` cannot parse.
# Used to test FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE.
case "$1" in
    version)
        echo "GibberishSSL build unknown"
        ;;
    list)
        echo "TLS 1.3 supported groups:"
        echo "  X25519MLKEM768:x25519:secp256r1"
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
