#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Fake openssl whose stdout/stderr boundary forms a misleading group line
# only if the two streams are concatenated without a separator.
case "$1" in
    s_client)
        printf "Negotiated TLS1.3 group:"
        printf "X25519MLKEM768\n" >&2
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
