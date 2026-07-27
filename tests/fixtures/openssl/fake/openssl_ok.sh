#!/usr/bin/env bash
# Fake openssl that satisfies capability detection but does not run probes.
case "$1" in
    version)
        echo "OpenSSL 3.6.3 7 Apr 2026"
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
