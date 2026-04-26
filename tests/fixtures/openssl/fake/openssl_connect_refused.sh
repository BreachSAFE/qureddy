#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Fake openssl that simulates a connection refused error.
# Used to test FailureCategory.TARGET_CONNECT_FAILED classification.
case "$1" in
    version)
        echo "OpenSSL 3.5.6 7 Apr 2026"
        ;;
    list)
        echo "X25519MLKEM768:x25519:secp256r1"
        ;;
    s_client)
        echo "Connecting to 192.0.2.1" >&2
        echo "connect:errno=61" >&2
        echo "connect:errno=61" >&2
        exit 1
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
