# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Certificate fetch + parse via OpenSSL subprocess only — MVP 0.2.

Promoted from prototype status by ADR 0005
(docs/contributors/adr/0005-cbom-schema-source-of-truth.md). Read-only — no
minting, no key generation, no private key material ever touched.

Rejected approach: the `cryptography` library. Per coding-rules.md §13.1 a
new dependency must replace 50+ lines we'd otherwise write; single-purpose
`openssl x509` flags (-subject/-issuer/-dates/-serial/-pubkey) do this in
under 40 lines with zero new dependencies, and it's the exact pattern
testssl.sh uses in production across years of real-world OpenSSL version
drift (verified: `reference/testssl/testssl.sh` greps confirm this). Thin
wrapper over the binary QuReddy already depends on — nothing new to add.

Kept out of openssl_probe.py (already 436 lines, past the 400-line hard
ceiling, tracked in issue #82) rather than adding to an over-ceiling file.
Still respects coding-rules.md §7: list-form args, shell=False, timeout on
every call, both streams captured, check=False with manual returncode
inspection.

ANTIPATTERN ACCEPTED: cert-verification-skip, because this is a read-only
analysis tool that must be able to observe and report on expired,
self-signed, and otherwise untrusted certificate chains (that's the whole
point — a scanner that refuses to look at a broken cert can't tell the
user it's broken). No trust decision is ever made on this data; nothing
downstream treats an unverified cert as verified.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from qureddy.core.errors import LocalOpenSSLMissing
from qureddy.core.logging import get_logger
from qureddy.scanners.tls._net import build_connect_target
from qureddy.scanners.tls.cert_sig import parse_certificate_signature

_log = get_logger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """Read-only summary of one observed certificate. Nothing here is minted."""

    subject: str
    issuer: str
    not_before: str
    not_after: str
    serial: str
    signature_algorithm: str
    public_key_summary: str
    is_self_signed: bool
    is_post_quantum_signature: bool
    """True iff `signature_algorithm` is a recognized ML-DSA (PQC) algorithm.

    Issue #183: cert_sig.py's classification existed but nothing called
    it, so the scan never reported the certificate/authentication axis
    and output hardcoded a false "remain classical" assertion. Wired in
    here rather than a second subprocess call: `parse_certificate`
    already fetches the `-text` output cert_sig.py's regex needs.
    """


def _run_openssl(
    args: list[str],
    *,
    event_prefix: str,
    timeout_seconds: int,
    input_text: str | None = None,
) -> str:
    """Shared subprocess.run + exception-mapping for both call shapes below.

    `fetch_certificate_pem` (no stdin, reads a live handshake) and `_x509`
    (PEM piped in via stdin) had identical timeout/missing-binary handling
    duplicated between them — same two exception branches, same log shape,
    only the args and stdin source differed. `event_prefix` keeps each call
    site's log event names distinct ("cert_probe.fetch.*" / "cert_probe.x509.*").

    Raises:
        LocalOpenSSLMissing: `args[0]` does not resolve to an executable.

    On timeout, returns "" rather than raising — a hung connection is not
    a local-dependency problem, it's a target-side condition the caller
    already has failure categories for.
    """
    _log.info(f"{event_prefix}.start", args=args, timeout_seconds=timeout_seconds)
    try:
        completed = subprocess.run(  # noqa: S603 -- list-form, shell=False
            args,
            input=input_text,
            stdin=subprocess.DEVNULL if input_text is None else None,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        _log.warning(f"{event_prefix}.timeout", args=args, timeout_seconds=timeout_seconds)
        return ""
    except FileNotFoundError as exc:
        _log.error(f"{event_prefix}.openssl_missing", openssl_path=args[0])
        raise LocalOpenSSLMissing(str(exc)) from exc

    _log.info(f"{event_prefix}.complete", return_code=completed.returncode)
    return completed.stdout


def fetch_certificate_pem(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Fetch the leaf certificate as PEM text via `openssl s_client`. Analysis mode: no -verify flags are set, so s_client will not abort the handshake over an invalid chain (expired/self-signed/untrusted certs are still captured via -showcerts).

    Raises:
        LocalOpenSSLMissing: `openssl_path` does not resolve to an executable.

    On timeout, returns "" (same as "no certificate observed") — see
    `_run_openssl`.
    """
    args = [openssl_path, "s_client", "-connect", build_connect_target(host, port), "-showcerts"]
    if sni is not None and sni.strip():
        args.extend(["-servername", sni])
    stdout = _run_openssl(args, event_prefix="cert_probe.fetch", timeout_seconds=timeout_seconds)
    pem_start = stdout.find("-----BEGIN CERTIFICATE-----")
    pem_end = stdout.find("-----END CERTIFICATE-----")
    if pem_start == -1 or pem_end == -1:
        return ""
    return stdout[pem_start : pem_end + len("-----END CERTIFICATE-----")]


def _x509(
    openssl_path: str, pem: str, *args: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
) -> str:
    """One `openssl x509 -noout <args>` call against in-memory PEM text.

    Raises:
        LocalOpenSSLMissing: `openssl_path` does not resolve to an executable.

    On timeout, returns "" — see `_run_openssl`.
    """
    full_args = [openssl_path, "x509", "-noout", *args]
    stdout = _run_openssl(
        full_args, event_prefix="cert_probe.x509", timeout_seconds=timeout_seconds, input_text=pem
    )
    return stdout.strip()


def parse_certificate(
    openssl_path: str, pem: str, *, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
) -> CertificateInfo:
    """Parse a PEM certificate using single-purpose `openssl x509` flags only — no `-text` full-dump parsing except the one field (signature algorithm) with no dedicated flag, same as testssl.sh.

    Raises:
        ValueError: `pem` is empty. Reviewer-flagged bug: on an empty PEM,
            every `-noout` call below returns "", so subject == issuer ==
            "" and is_self_signed silently comes out True — a failed
            fetch must not look identical to a genuine self-signed cert.
            Callers check `if pem:` before calling this (see cli.py); this
            guard exists so the function is correct even if a future
            caller doesn't.

    Issue #253: each of the five `_x509` calls below defaulted to its own
    30-second timeout regardless of what the caller's own `--timeout`
    requested (`fetch_certificate_pem` threaded it correctly; this
    function didn't) — up to 150s in this stage alone on a slow/hanging
    local OpenSSL. `timeout_seconds` is now threaded through every call.
    """
    if not pem.strip():
        msg = "cannot parse empty certificate PEM"
        raise ValueError(msg)
    subject = (
        _x509(openssl_path, pem, "-subject", timeout_seconds=timeout_seconds)
        .removeprefix("subject=")
        .strip()
    )
    issuer = (
        _x509(openssl_path, pem, "-issuer", timeout_seconds=timeout_seconds)
        .removeprefix("issuer=")
        .strip()
    )
    dates = _x509(openssl_path, pem, "-dates", timeout_seconds=timeout_seconds)
    not_before = next(
        (
            line.removeprefix("notBefore=")
            for line in dates.splitlines()
            if line.startswith("notBefore=")
        ),
        "",
    )
    not_after = next(
        (
            line.removeprefix("notAfter=")
            for line in dates.splitlines()
            if line.startswith("notAfter=")
        ),
        "",
    )
    serial = (
        _x509(openssl_path, pem, "-serial", timeout_seconds=timeout_seconds)
        .removeprefix("serial=")
        .strip()
    )
    pubkey_text = _x509(openssl_path, pem, "-text", timeout_seconds=timeout_seconds)
    # cert_sig.py's regex replaces the previous hand-rolled substring search
    # ("Signature Algorithm" in line) — same source text, but anchored
    # (^...$, MULTILINE) rather than a loose substring match, and it also
    # classifies PQC vs classical in the same pass (issue #183).
    cert_sig = parse_certificate_signature(pubkey_text)
    sig_alg = cert_sig.raw_algorithm or "UNKNOWN"
    pubkey_line = next((line for line in pubkey_text.splitlines() if "Public-Key:" in line), "")
    pubkey_summary = pubkey_line.strip() or "UNKNOWN"
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        signature_algorithm=sig_alg,
        public_key_summary=pubkey_summary,
        is_post_quantum_signature=cert_sig.is_post_quantum,
        # Issue #217: `subject == issuer` alone is also true when BOTH are
        # independently empty (a partial `_x509` sub-call timeout/failure
        # on just -subject/-issuer, not the whole-PEM-empty case the
        # docstring above already guards). A real self-signed cert has a
        # genuinely matching *non-empty* subject/issuer; require that.
        is_self_signed=bool(subject) and subject == issuer,
    )
