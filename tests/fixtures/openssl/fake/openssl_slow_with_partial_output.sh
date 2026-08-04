#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Fake openssl that writes partial output, then sleeps past the timeout.
# Used to verify that subprocess.TimeoutExpired-driven ProbeResult
# preserves the bytes the process produced before the kill, instead of
# discarding them as the legacy code did.
case "$1" in
    s_client)
        printf "Connecting to 192.0.2.99\nCONNECTION ESTABLISHED\n" >&2
        printf "partial-stdout-marker\n"
        # Sleep well past any reasonable test timeout so the subprocess
        # is killed by TimeoutExpired before it can exit cleanly.
        sleep 30
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
