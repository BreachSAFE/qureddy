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
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

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


def _is_self_signed(
    openssl_path: str,
    pem: str,
    subject: str,
    issuer: str,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> bool:
    """True iff the certificate is both self-issued AND self-signed — issue #224.

    Equal subject/issuer DNs prove only "self-issued" — a certificate can have
    a matching subject and issuer while being signed by a completely different
    key (confirmed live: a real cert with subject==issuer=='CN=Same Name' whose
    signature was created by a separate issuer key; `openssl verify
    -check_ss_sig` correctly rejects it, exit code 2, "certificate signature
    failure"). DN equality is used here only as a cheap precondition to decide
    whether the expensive cryptographic check below is worth running — the
    verdict comes from the check, never from the DN comparison alone.

    `openssl verify -check_ss_sig` needs the cert as a real file (both
    `-CAfile` and the cert-to-verify argument), not stdin, unlike `_x509`'s
    pattern — a securely-created temp file is written and removed in `finally`.

    Any ambiguity (subprocess timeout, nonzero exit for any reason, missing
    subject/issuer) resolves to `False`, never `True` — this field asserts a
    positive cryptographic claim, so absence of proof must not read as proof.
    A three-state true/false/undetermined model is the more complete answer
    but changes this project's public `CertificateInfo`/`Evidence` shape,
    which needs the same maintainer-authority schema decision as #226/#230 —
    out of scope for this bounded fix.
    """
    if not subject or subject != issuer:
        return False
    cert_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(pem)
            cert_path = f.name
        args = [openssl_path, "verify", "-check_ss_sig", "-CAfile", cert_path, cert_path]
        completed = subprocess.run(  # noqa: S603 -- list-form, shell=False, validated args
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    finally:
        if cert_path is not None:
            with suppress(OSError):
                Path(cert_path).unlink()
    return completed.returncode == 0


def _x509_value(
    openssl_path: str,
    pem: str,
    flag: str,
    prefix: str,
    timeout_seconds: int,
) -> str:
    """Read one scalar x509 field and remove OpenSSL's field prefix."""
    return (
        _x509(openssl_path, pem, flag, timeout_seconds=timeout_seconds).removeprefix(prefix).strip()
    )


def _certificate_dates(openssl_path: str, pem: str, timeout_seconds: int) -> tuple[str, str]:
    """Read the not-before and not-after fields from one x509 call."""
    dates = _x509(openssl_path, pem, "-dates", timeout_seconds=timeout_seconds)
    values = {
        name: next(
            (line.removeprefix(prefix) for line in dates.splitlines() if line.startswith(prefix)),
            "",
        )
        for name, prefix in (("before", "notBefore="), ("after", "notAfter="))
    }
    return values["before"], values["after"]


def _certificate_text_details(
    openssl_path: str, pem: str, timeout_seconds: int
) -> tuple[str, str, bool]:
    """Read signature and public-key details from the x509 text output."""
    text = _x509(openssl_path, pem, "-text", timeout_seconds=timeout_seconds)
    cert_sig = parse_certificate_signature(text)
    public_key_line = next((line for line in text.splitlines() if "Public-Key:" in line), "")
    return (
        cert_sig.raw_algorithm or "UNKNOWN",
        public_key_line.strip() or "UNKNOWN",
        cert_sig.is_post_quantum,
    )


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
    subject = _x509_value(openssl_path, pem, "-subject", "subject=", timeout_seconds)
    issuer = _x509_value(openssl_path, pem, "-issuer", "issuer=", timeout_seconds)
    not_before, not_after = _certificate_dates(openssl_path, pem, timeout_seconds)
    serial = _x509_value(openssl_path, pem, "-serial", "serial=", timeout_seconds)
    sig_alg, pubkey_summary, is_post_quantum = _certificate_text_details(
        openssl_path, pem, timeout_seconds
    )
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        signature_algorithm=sig_alg,
        public_key_summary=pubkey_summary,
        is_post_quantum_signature=is_post_quantum,
        # Issue #224: subject==issuer proves only "self-issued" — a real
        # cryptographic signature check (_is_self_signed) is required to
        # tell that apart from "self-issued but signed by a different key".
        # #217's empty-subject/issuer guard is now subsumed by
        # _is_self_signed's own `if not subject` precondition.
        is_self_signed=_is_self_signed(
            openssl_path, pem, subject, issuer, timeout_seconds=timeout_seconds
        ),
    )
