#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Fake openssl that exists and is executable, but fails during capability detection.
# Used to test FailureCategory.LOCAL_OPENSSL_BROKEN.
case "$1" in
    version)
        echo "dyld: Library not loaded: libssl.dylib" >&2
        exit 139
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
