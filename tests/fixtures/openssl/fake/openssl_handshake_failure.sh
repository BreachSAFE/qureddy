#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Fake openssl that simulates a TLS handshake failure (badssl tls1.2 shape).
# Used to test FailureCategory.TLS_HANDSHAKE_FAILED classification when
# the failure is an actual handshake-layer alert, not a connect error.
case "$1" in
    version)
        echo "OpenSSL 3.5.6 7 Apr 2026"
        ;;
    list)
        echo "X25519MLKEM768:x25519:secp256r1"
        ;;
    s_client)
        echo "Connecting to 104.154.89.105" >&2
        echo "C0605FFA01000000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:ssl/record/rec_layer_s3.c:918:SSL alert number 40" >&2
        exit 1
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
