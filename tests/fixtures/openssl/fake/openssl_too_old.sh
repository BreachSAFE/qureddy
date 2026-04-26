#!/usr/bin/env bash
# Fake openssl: claims version 3.4.0, returns a typical TLS 1.3 group list.
# Used to test FailureCategory.LOCAL_OPENSSL_TOO_OLD.
case "$1" in
    version)
        echo "OpenSSL 3.4.0 1 Jan 2026"
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
