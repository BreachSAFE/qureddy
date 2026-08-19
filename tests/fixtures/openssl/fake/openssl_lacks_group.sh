#!/usr/bin/env bash
# Fake openssl: pinned version 3.5.7 (passes the version gate) but lists no
# X25519MLKEM768 group. Tests FailureCategory.LOCAL_OPENSSL_LACKS_GROUP.
case "$1" in
    version)
        echo "OpenSSL 3.5.7 1 Apr 2026"
        ;;
    list)
        echo "TLS 1.3 supported groups:"
        echo "  x25519:secp256r1:secp384r1:secp521r1"
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
