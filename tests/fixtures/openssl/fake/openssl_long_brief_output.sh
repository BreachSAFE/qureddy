#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Fake openssl with a successful s_client -brief output whose group line
# appears after EXCERPT_LIMIT. Used to prove parsing is not capped by JSON
# excerpt length.
case "$1" in
    s_client)
        python3 - <<'PY'
print("certificate-chain-padding-" * 220)
print("Protocol version: TLSv1.3")
print("Ciphersuite: TLS_AES_256_GCM_SHA384")
print("Negotiated TLS1.3 group: X25519MLKEM768")
PY
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
