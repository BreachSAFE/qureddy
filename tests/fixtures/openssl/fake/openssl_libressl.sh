#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Fake openssl reproducing real macOS /usr/bin/openssl (LibreSSL 3.3.6),
# captured via `/usr/bin/openssl version` and
# `/usr/bin/openssl list -tls1_3 -tls-groups` on macOS 26 (issue #10).
# Used to test FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL.
case "$1" in
    version)
        echo "LibreSSL 3.3.6"
        ;;
    list)
        # Real LibreSSL exits 0 on an unrecognized subcommand, printing
        # the "invalid command" notice to stderr and nothing to stdout.
        echo "openssl:Error: 'list' is an invalid command." >&2
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
