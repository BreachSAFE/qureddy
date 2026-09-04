# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Legacy TLS protocol + full cipher-suite enumeration (issue #192).

`openssl_probe.py` only ever asks "does this target negotiate the one
PQC-relevant hybrid/classical group on TLS 1.3?" — real, but a narrower
question than "what is this target's whole protocol/cipher surface,"
which is what a credible "PQC readiness" claim needs (independent TLS
scanners found TLS 1.0/1.1 and a SWEET32-vulnerable 3DES cipher on a
target qureddy reported clean on, because qureddy never asked).

Kept out of `openssl_probe.py` (already near its 400-line hard ceiling,
issue #82) rather than adding to an over-ceiling file, same reasoning
as `cert_probe.py`.

## Why `@SECLEVEL=0` is required, and why this still works on the
## project's required OpenSSL 3.5.7 LTS pin

OpenSSL 3.x's default security level (1) refuses TLS < 1.2 and most
legacy ciphers outright — confirmed live: `openssl s_client -tls1`
against a real target fails with "no protocols available" on a stock
OpenSSL 3.x build. This is a *security-level* gate, not a compile-time
one: appending `@SECLEVEL=0` to the `-cipher` string restores TLS 1.0/
1.1 negotiation on the same binary (confirmed live against real
targets: `pq.cloudflareresearch.com` negotiates TLSv1 with SECLEVEL=0,
fails without it). No second, legacy-enabled OpenSSL build is needed —
unlike testssl.sh, which historically vendors its own OpenSSL for
exactly this reason.

## Why iterative exclusion, not one-cipher-at-a-time

A naive sweep (try each of OpenSSL's ~65 known TLS 1.2 cipher names
individually) is O(candidate_count) handshakes per protocol — correct
but slow. Offering the *entire* remaining candidate list each round and
recording whichever one the server actually picks (its real preference
order) turns this into O(accepted_count) handshakes per protocol —
the same method testssl.sh uses. Measured live: ~65-100ms per real
handshake; a full TLS 1.0/1.1/1.2 sweep against a real target completes
in the 10s-of-seconds range, not minutes.

ANTIPATTERN ACCEPTED: cert-verification-skip (inherited from the same
reasoning as `cert_probe.py` — this must observe what a target actually
offers, including deliberately-weak configurations, not refuse to look).

## Known gap: RC4/3DES/DES are not detectable on this build (issue #192 follow-up)

Confirmed live: on the OpenSSL 3.5.7 LTS build this project requires (needed
for PQC group support), RC4, 3DES, and DES are compiled out entirely —
`openssl ciphers -s -tls1 'ALL:COMPLEMENTOFALL:@SECLEVEL=0'` never lists
them, and an explicit `-cipher RC4-SHA` / `DES-CBC3-SHA` handshake fails
with "no cipher match" regardless of SECLEVEL. This is a compile-time
absence, not a security-level gate `@SECLEVEL=0` can restore (unlike
TLS 1.0/1.1 themselves, which *are* just SECLEVEL-gated and do work
here). Only `NULL`-cipher and `MD5`-based ciphers remain negotiable as
"weak" on this binary. Matching an independent scanner's exact
3DES/SWEET32 detection depth would need a second, separately-provisioned legacy
OpenSSL build (testssl.sh's own approach) — real new packaging
complexity, deliberately out of scope for this pass. `WEAK_CIPHER_MARKERS`
below still lists RC4/3DES/DES/RC2/EXPORT for forward-compatibility
(harmless — they will simply never match on this build) and so the
intent is documented for whoever picks up the second-build follow-up.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from qureddy.core.logging import get_logger
from qureddy.scanners.tls.connection import StartTLSMode, build_s_client_args
from qureddy.scanners.tls.openssl_probe.executor import LaunchStatus, raise_for_launch
from qureddy.scanners.tls.openssl_probe.executor import run_openssl as execute

_log = get_logger(__name__)

# NOT parse.py's CIPHERSUITE regex: that pattern (`[A-Z0-9_]+`) is
# written for TLS 1.3's IANA underscore-style names
# (TLS_AES_128_GCM_SHA256), the only cipher-name shape
# openssl_probe.py's forced-TLS-1.3 probes ever see. Legacy TLS
# 1.0-1.2 cipher names use OpenSSL's hyphenated "classic" naming
# convention (ECDHE-RSA-AES256-SHA) — confirmed live, the shared
# regex silently matched nothing against real legacy-protocol output
# during development of this module. Two genuinely different name
# grammars, not one regex two ways to write it.
_LEGACY_CIPHERSUITE = re.compile(
    r"^[^\S\r\n]*Ciphersuite:[^\S\r\n]*(?P<cipher>[A-Z0-9_-]+)[^\S\r\n]*$",
    re.MULTILINE,
)

DEFAULT_TIMEOUT_SECONDS = 10
_SECLEVEL_OVERRIDE = "@SECLEVEL=0"

# SSLv2/SSLv3 intentionally excluded: OpenSSL 3.x does not compile them
# in at all (unlike TLS 1.0/1.1, which are merely SECLEVEL-gated), so no
# flag on this binary can restore them — a genuinely different, EOL-only
# build would be required, out of scope here.
LEGACY_PROTOCOLS: tuple[tuple[str, str], ...] = (
    ("-tls1", "TLSv1"),
    ("-tls1_1", "TLSv1.1"),
    ("-tls1_2", "TLSv1.2"),
)


# Weak-cipher markers and their protocol-neutral predicate live in
# ``qureddy.core.ciphers`` so output adapters and future scanners share one
# source of truth.
@dataclass(frozen=True, slots=True)
class LegacyProtocolResult:
    """Outcome of one protocol's cipher-enumeration sweep."""

    protocol_flag: str
    protocol_version: str
    offered: bool
    accepted_ciphers: tuple[str, ...]
    probe_incomplete: bool = False
    """True when a subprocess timeout cut the sweep short — issue #246.

    Distinct from a genuine, complete "server rejects every candidate"
    result: `offered=False` alone doesn't distinguish "we asked and the
    answer was no" from "we don't know, the probe never finished."
    """


def _run_openssl(
    args: list[str], *, event_prefix: str, timeout_seconds: int
) -> subprocess.CompletedProcess[str] | None:
    """One openssl call via the executor; returns None on timeout (degrade).

    Callers read ``.returncode`` / ``.stdout`` / ``.stderr`` off the returned
    ``CompletedProcess``, so the executor outcome is re-wrapped into one to keep
    those call sites unchanged. A missing or unlaunchable binary now raises the
    typed exit-3 error via ``raise_for_launch`` (the OSError was previously
    uncaught and crashed the sweep).
    """
    _log.info(f"{event_prefix}.start", args=args, timeout_seconds=timeout_seconds)
    outcome = execute(args, timeout_seconds=timeout_seconds)
    if outcome.timed_out:
        _log.warning(f"{event_prefix}.timeout", args=args, timeout_seconds=timeout_seconds)
        return None
    if outcome.launch is not LaunchStatus.OK:
        _log.error(f"{event_prefix}.openssl_unlaunchable", openssl_path=args[0])
    raise_for_launch(outcome, args[0])
    _log.info(f"{event_prefix}.complete", return_code=outcome.returncode)
    return_code = outcome.returncode
    assert return_code is not None  # noqa: S101 -- OK launch guarantees an exit code
    return subprocess.CompletedProcess(args, return_code, outcome.stdout, outcome.stderr)


def _candidate_ciphers(
    openssl_path: str, protocol_flag: str, *, timeout_seconds: int
) -> tuple[list[str], bool]:
    """List every cipher name this OpenSSL build knows for `protocol_flag`.

    Seeds the candidate set from the local binary's own knowledge
    (`openssl ciphers -s <flag> ...`) rather than a hand-maintained
    table — avoids drifting from whatever names this specific OpenSSL
    build actually uses.

    Returns `(candidates, timed_out)`. Issue #246: a subprocess timeout
    (`completed is None`) is a "we don't know" outcome, not the same
    thing as this OpenSSL build genuinely listing zero ciphers for the
    protocol (which never happens in practice) — the caller must be
    able to tell these apart instead of both collapsing to `[]`.
    """
    args = [
        openssl_path,
        "ciphers",
        "-s",
        protocol_flag,
        f"ALL:COMPLEMENTOFALL:{_SECLEVEL_OVERRIDE}",
    ]
    completed = _run_openssl(
        args, event_prefix="legacy_probe.candidates", timeout_seconds=timeout_seconds
    )
    if completed is None:
        return [], True
    if completed.returncode != 0 or not completed.stdout.strip():
        return [], False
    return completed.stdout.strip().split(":"), False


def _handshake_with_cipher_list(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    protocol_flag: str,
    cipher_list: list[str],
    *,
    timeout_seconds: int,
    starttls: StartTLSMode | None = None,
) -> tuple[str | None, bool]:
    """One handshake offering `cipher_list`.

    Returns `(negotiated_cipher_or_None, timed_out)` — issue #246, same
    distinction as `_candidate_ciphers`: a timeout mid-sweep must not
    look identical to the server cleanly rejecting every remaining
    candidate.
    """
    args = build_s_client_args(
        openssl_path,
        host,
        port,
        sni,
        extra=(
            protocol_flag,
            "-cipher",
            ":".join([*cipher_list, _SECLEVEL_OVERRIDE]),
            "-brief",
        ),
        starttls=starttls,
    )
    completed = _run_openssl(
        args, event_prefix="legacy_probe.handshake", timeout_seconds=timeout_seconds
    )
    if completed is None:
        return None, True
    if completed.returncode != 0:
        return None, False
    # `-brief` output lands on stderr, not stdout, for some handshake
    # outcomes (confirmed live) — same quirk openssl_probe.py's
    # `_combined_probe_output` already handles. Joined with `\n`, not
    # concatenated bare, per the project's own trap list (#9): an
    # unseparated join can produce a synthetic line that satisfies a
    # MULTILINE regex across what were two genuinely separate streams.
    combined = f"{completed.stdout}\n{completed.stderr}"
    match = _LEGACY_CIPHERSUITE.search(combined)
    return (match.group("cipher") if match else None), False


def probe_legacy_protocol(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    protocol_flag: str,
    protocol_version: str,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    starttls: StartTLSMode | None = None,
) -> LegacyProtocolResult:
    """Iterative-exclusion cipher enumeration for one legacy protocol version.

    Offers the full remaining candidate list each round; the server's
    picked cipher is removed before the next round, so this terminates
    in accepted-cipher-count rounds, not candidate-count rounds.
    """
    _log.info("legacy_probe.protocol.start", protocol=protocol_version)
    remaining, incomplete = _candidate_ciphers(
        openssl_path, protocol_flag, timeout_seconds=timeout_seconds
    )
    accepted: list[str] = []
    while remaining:
        cipher, timed_out = _handshake_with_cipher_list(
            openssl_path,
            host,
            port,
            sni,
            protocol_flag,
            remaining,
            timeout_seconds=timeout_seconds,
            starttls=starttls,
        )
        if timed_out:
            incomplete = True
            break
        if cipher is None or cipher not in remaining:
            break
        accepted.append(cipher)
        remaining.remove(cipher)
    result = LegacyProtocolResult(
        protocol_flag=protocol_flag,
        protocol_version=protocol_version,
        offered=bool(accepted),
        accepted_ciphers=tuple(accepted),
        probe_incomplete=incomplete,
    )
    _log.info(
        "legacy_probe.protocol.complete",
        protocol=protocol_version,
        offered=result.offered,
        incomplete=result.probe_incomplete,
    )
    return result


def probe_all_legacy_protocols(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    starttls: StartTLSMode | None = None,
) -> tuple[LegacyProtocolResult, ...]:
    """Run `probe_legacy_protocol` for every version in `LEGACY_PROTOCOLS`."""
    return tuple(
        probe_legacy_protocol(
            openssl_path,
            host,
            port,
            sni,
            flag,
            version,
            timeout_seconds=timeout_seconds,
            starttls=starttls,
        )
        for flag, version in LEGACY_PROTOCOLS
    )
