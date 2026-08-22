# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Target string parser and normalizer."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import ParseResult, urlparse

from pydantic import ValidationError

from qureddy.core.errors import TargetParseError
from qureddy.core.models import HOSTNAME_PATTERN, ScanTarget


def _build_scan_target(
    *,
    original_input: str,
    host: str,
    port: int,
    locator: str,
    sni: str | None = None,
    scheme: str = "tls",
) -> ScanTarget:
    """Build a ``ScanTarget``, converting pydantic errors to ``TargetParseError``.

    The parsers promise to raise only ``TargetParseError`` (never a pydantic
    error). A host that clears the string-level checks but still trips a
    ``ScanTarget`` field validator (e.g. a bracket-bearing IPv6-ish value, found
    by the SSH-target fuzz harness) must surface as ``TargetParseError``, not a
    leaked ``ValidationError``.
    """
    try:
        return ScanTarget(
            original_input=original_input,
            host=host,
            port=port,
            sni=sni,
            scheme=scheme,
            locator=locator,
        )
    except ValidationError as exc:
        detail = exc.errors()[0].get("msg", "invalid target") if exc.errors() else "invalid target"
        raise TargetParseError(f"invalid target: {detail}") from exc


DEFAULT_PORT = 443
# HOSTNAME_PATTERN is imported from core.models (its canonical home; #315).
MIN_PORT = 1
MAX_PORT = 65535

# Issue #255: HOSTNAME_PATTERN's dotted-label grammar happens to also
# accept legacy/noncanonical numeric IPv4 forms (decimal "2130706433",
# short "127.1", zero-padded "127.000.000.001") that ipaddress.ip_address
# correctly rejects as not-strictly-canonical. The OS resolver still
# canonicalizes these to a real (different-looking) address, so QuReddy
# would report scanning one string while the subprocess actually connects
# to another. Reject anything that reads as "digits and dots only" and
# isn't already a strict IP literal, rather than silently accepting it as
# a DNS hostname.
_NUMERIC_HOST = re.compile(r"^[0-9.]+$")
# Plain ASCII digits only: `int()` would also accept Unicode digits, underscores,
# a leading sign, and surrounding whitespace (see _parse_port / #128).
_CANONICAL_PORT = re.compile(r"[0-9]+")


def parse_target(
    input_str: str, sni_override: str | None = None, *, block_internal: bool = False
) -> ScanTarget:
    """Parse a user-supplied target string into a normalized ScanTarget.

    Args:
        input_str: User input. Accepts hostname, host:port, https URL, or IP.
        sni_override: Optional SNI override for a name-based virtual host.
            Recommended (not required) for IP targets serving multiple certs.
        block_internal: Reject loopback/link-local/private/metadata targets. Off by
            default (the CLI operator deliberately chooses the target); an embedder
            that accepts an untrusted target should enable it to prevent SSRF into
            cloud instance-metadata or internal services (#134).

    Returns:
        Normalized ScanTarget with locator format ``tls://host:port``.

    Raises:
        TargetParseError: If input cannot be parsed into a valid target.
    """
    if not isinstance(input_str, str):
        raise TargetParseError("target must be a string")

    cleaned = input_str.strip()
    if not cleaned:
        raise TargetParseError("target is empty")

    host, port = _extract_host_port(cleaned)
    host, is_ip = _validate_and_classify_host(
        host, invalid_prefix="target host is not a valid hostname or IP"
    )
    _reject_internal_target(host, block_internal=block_internal)
    sni = _resolve_sni(host, sni_override, is_ip=is_ip)

    # Issue #236: an unbracketed IPv6 host glued directly to ":{port}" in
    # the locator is the same ambiguous shape #223 rejects on the input
    # side — ScanTarget's own locator_matches_endpoint validator now
    # requires the bracketed form, which this was silently not producing.
    rendered_host = f"[{host}]" if ":" in host else host
    return _build_scan_target(
        original_input=input_str,
        host=host,
        port=port,
        sni=sni,
        locator=f"tls://{rendered_host}:{port}",
    )


def _validate_and_classify_host(host: str, *, invalid_prefix: str) -> tuple[str, bool]:
    """Strip the FQDN root dot, then classify/validate the host, returning ``(host, is_ip)``.

    Rejects noncanonical numeric IP forms (#255) and non-hostname/non-IP input. The
    ``invalid_prefix`` lets each caller (TLS vs SSH) keep its own error wording while
    sharing this validation.
    """
    host = _strip_fqdn_root_dot(host)
    is_ip = _is_ip_literal(host)
    if not is_ip and _NUMERIC_HOST.fullmatch(host):
        msg = (
            f"noncanonical numeric IP target {host!r}; "
            "use canonical dotted-decimal IPv4 (for example 127.0.0.1)"
        )
        raise TargetParseError(msg)
    if not is_ip and not HOSTNAME_PATTERN.match(host):
        raise TargetParseError(f"{invalid_prefix}: {host!r}")
    return host, is_ip


def _resolve_sni(host: str, sni_override: str | None, *, is_ip: bool) -> str | None:
    """Resolve the on-wire SNI: the validated override, else the host (None for an IP)."""
    if sni_override is not None:
        if not sni_override.strip():
            raise TargetParseError("--sni cannot be empty or whitespace-only")
        # The derived SNI (sni = host) is validated by HOSTNAME_PATTERN; the override must
        # meet the same bar or a newline/control char/ANSI escape/leading dash flows verbatim
        # into OpenSSL's -servername value (#145). fullmatch (not match) because `$` also
        # matches just before a trailing newline, which would let "host\n" through.
        if not HOSTNAME_PATTERN.fullmatch(sni_override):
            msg = f"--sni is not a valid hostname: {sni_override!r}"
            raise TargetParseError(msg)
        return sni_override
    if is_ip:
        return None
    return host


def _extract_host_port(cleaned: str) -> tuple[str, int]:
    """Pull (host, port) out of any of the accepted input shapes."""
    if "://" in cleaned:
        return _extract_url_host_port(cleaned)

    if cleaned.startswith("[") and "]" in cleaned:
        return _parse_bracketed_ipv6(cleaned)

    if cleaned.count(":") == 1:
        host, _, raw_port = cleaned.partition(":")
        if not host:
            raise TargetParseError("target host is empty")
        return host, _parse_port(raw_port)

    _reject_ambiguous_unbracketed_ipv6(cleaned)
    return cleaned, DEFAULT_PORT


def _extract_url_host_port(cleaned: str) -> tuple[str, int]:
    """Pull (host, port) out of an ``https://``/``tls://`` URL form."""
    try:
        parsed = urlparse(cleaned)
    except ValueError as exc:
        # urlparse raises ValueError eagerly on a malformed authority (e.g. an
        # unclosed "[" IPv6 bracket); that is bad user input (exit 4), not an
        # internal error (exit 70). (#139)
        raise TargetParseError(f"malformed target URL: {cleaned!r}") from exc
    if parsed.scheme not in {"https", "tls"}:
        msg = f"unsupported scheme {parsed.scheme!r}; expected https or tls"
        raise TargetParseError(msg)
    _reject_tls_uri_extras(parsed)
    host = parsed.hostname
    if not host:
        raise TargetParseError("URL has no host component")
    try:
        port = parsed.port if parsed.port is not None else DEFAULT_PORT
    except ValueError as exc:
        msg = "URL contains an invalid port"
        raise TargetParseError(msg) from exc
    return host, _validate_port(port)


def _reject_uri_credentials(parsed: ParseResult, *, scheme_label: str) -> None:
    """Reject userinfo (user[:password]@) in a URI — shared by TLS and SSH."""
    if parsed.username is not None or parsed.password is not None:
        raise TargetParseError(f"{scheme_label} target must not contain credentials")


def _reject_tls_uri_extras(parsed: ParseResult) -> None:
    """Reject credentials/path/query/fragment in an https/tls URL (#366).

    The URL parser previously kept only host+port and silently dropped
    everything else, so ``https://alice:secret@example.com/p?x#f`` scanned
    ``example.com:443`` with the credentials and path discarded. Mirror the SSH
    parser's ``_reject_ssh_uri_extras`` and reject that data instead. A bare
    trailing "/" (``urlparse`` path "/") is the one accepted path form; any real
    path, params, query, or fragment is rejected.
    """
    _reject_uri_credentials(parsed, scheme_label="TLS")
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise TargetParseError("TLS target URL must not contain a path, query, or fragment")


def _reject_ambiguous_unbracketed_ipv6(cleaned: str) -> None:
    """Reject a colon-heavy target that reads as two different valid answers.

    An unbracketed string like ``::1:8443`` is itself a syntactically valid
    IPv6 address (RFC 4291) *and* could plausibly mean host ``::1`` port
    ``8443`` — genuinely ambiguous, not merely unusual. Plain colon-counting
    (`>1`) is not sufficient: an ordinary bare IPv6 literal like ``::1`` also
    has two colons but is unambiguous, because its rpartition prefix (``:``)
    is not itself a valid IP. Only reject when *both* readings are valid.
    """
    if not _is_ip_literal(cleaned):
        return
    prefix, _, suffix = cleaned.rpartition(":")
    if prefix and suffix.isdigit() and _is_ip_literal(prefix):
        msg = (
            f"ambiguous IPv6 target {cleaned!r} -- bracket it: "
            f"use [{prefix}]:{suffix} if you meant host {prefix!r} port {suffix}, "
            f"or [{cleaned}] if you meant the literal address {cleaned!r}"
        )
        raise TargetParseError(msg)


def _parse_bracketed_ipv6(cleaned: str) -> tuple[str, int]:
    closing = cleaned.index("]")
    host = cleaned[1:closing]
    remainder = cleaned[closing + 1 :]
    if remainder == "":
        return host, DEFAULT_PORT
    if not remainder.startswith(":"):
        raise TargetParseError("malformed IPv6 target literal")
    return host, _parse_port(remainder[1:])


def _strip_fqdn_root_dot(host: str) -> str:
    """Normalize an absolute FQDN by removing its single trailing root dot.

    A single trailing dot is the canonical absolute-FQDN form (RFC 1034 section
    3.1, the explicit root label) and is a valid target, but the stored host,
    the locator, and the on-wire SNI (RFC 6066 section 3) must omit it. Two or
    more trailing dots is an empty label and stays malformed so downstream
    hostname validation still rejects it.
    """
    if host.endswith(".") and not host.endswith(".."):
        return host[:-1]
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


# Hostnames that resolve to the cloud instance-metadata service on major providers.
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata", "instance-data"})


def _is_internal_host(host: str) -> bool:
    """Return True for a loopback/link-local/private/reserved/metadata target.

    IP literals are classified with ``ipaddress`` (link-local covers the
    169.254.169.254 metadata endpoint). A small hostname blocklist catches the
    well-known metadata names; arbitrary hostnames that *resolve* to an internal
    address are NOT caught here (that needs resolve-then-check) and are called out
    in the threat model.
    """
    lowered = host.lower()
    if lowered in _METADATA_HOSTS or lowered.endswith(".internal"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _reject_internal_target(host: str, *, block_internal: bool) -> None:
    """Raise when an internal target is blocked by the opt-in SSRF guard (#134)."""
    if block_internal and _is_internal_host(host):
        msg = (
            f"target {host!r} is an internal, link-local, or metadata endpoint; "
            "blocked by the internal-target guard (unset QUREDDY_BLOCK_INTERNAL_TARGETS "
            "to allow it)"
        )
        raise TargetParseError(msg)


def _validate_port(port: int) -> int:
    if not MIN_PORT <= port <= MAX_PORT:
        msg = f"port out of range [1, 65535]: {port}"
        raise TargetParseError(msg)
    return port


def _parse_port(raw_port: str) -> int:
    """Parse a port from its literal target text, rejecting non-canonical forms.

    `int()` alone silently accepts Unicode digits, underscores, a leading sign,
    and surrounding whitespace, so the scanner would record the string the user
    typed while connecting to a different, "corrected" port. This is the class
    already closed for numeric hosts (#255). Require plain ASCII digits, then
    range-check. The `urlparse`-based paths already reject these, so this keeps
    the bare `host:port` form consistent with the `scheme://` form (#128).
    """
    if not _CANONICAL_PORT.fullmatch(raw_port):
        msg = f"port is not a canonical number: {raw_port!r}"
        raise TargetParseError(msg)
    return _validate_port(int(raw_port))


DEFAULT_SSH_PORT = 22


def parse_ssh_target(input_str: str, *, block_internal: bool = False) -> ScanTarget:
    """Parse an SSH target into a normalized ``ssh://`` ScanTarget.

    Accepted forms are a hostname or IP with an optional port, plus an
    ``ssh://`` or ``sftp://`` URI containing only that endpoint. Credentials,
    paths, query strings, fragments, and foreign schemes are rejected before
    any network operation. ``block_internal`` opt-in rejects internal/metadata
    targets for embedders that accept an untrusted target (#134).
    """
    if not isinstance(input_str, str):
        raise TargetParseError("target must be a string")
    cleaned = input_str.strip()
    if not cleaned:
        msg = "empty target"
        raise TargetParseError(msg)

    if "://" in cleaned:
        host, port = _parse_ssh_uri(cleaned)
    else:
        host, port = _parse_raw_ssh_endpoint(cleaned)
    host, _ = _validate_and_classify_host(host, invalid_prefix="invalid SSH host")
    _reject_internal_target(host, block_internal=block_internal)
    rendered = f"[{host}]" if ":" in host else host
    return _build_scan_target(
        original_input=input_str,
        host=host,
        port=port,
        sni=None,
        scheme="ssh",
        locator=f"ssh://{rendered}:{port}",
    )


def _parse_ssh_uri(cleaned: str) -> tuple[str, int]:
    """Parse the allowlisted endpoint-only SSH/SFTP URI forms."""
    try:
        parsed = urlparse(cleaned)
    except ValueError as exc:
        # Malformed authority (e.g. unclosed "[" IPv6 bracket) is bad user input
        # (exit 4), not an internal error (exit 70). (#139)
        raise TargetParseError(f"malformed SSH target URL: {cleaned!r}") from exc
    if parsed.scheme not in {"ssh", "sftp"}:
        msg = f"unsupported SSH scheme {parsed.scheme!r}; expected ssh or sftp"
        raise TargetParseError(msg)
    _reject_ssh_uri_extras(parsed)
    if not parsed.hostname:
        raise TargetParseError("SSH target URI has no host component")
    try:
        port = parsed.port if parsed.port is not None else DEFAULT_SSH_PORT
    except ValueError as exc:
        raise TargetParseError("SSH target URI contains an invalid port") from exc
    return parsed.hostname, _validate_port(port)


def _reject_ssh_uri_extras(parsed: ParseResult) -> None:
    """Reject credentials, paths, queries, and fragments in an SSH/SFTP URI."""
    _reject_uri_credentials(parsed, scheme_label="SSH")
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        raise TargetParseError("SSH target URI must not contain a path, query, or fragment")


def _parse_raw_ssh_endpoint(cleaned: str) -> tuple[str, int]:
    """Parse a raw SSH host, host:port, or bracketed IPv6 endpoint."""
    if any(marker in cleaned for marker in ("/", "?", "#", "@")):
        raise TargetParseError("SSH target must be an endpoint without credentials or a path")
    if cleaned.startswith("[") and "]" in cleaned:
        closing = cleaned.index("]")
        host, remainder = cleaned[1:closing], cleaned[closing + 1 :]
        if not remainder:
            return host, DEFAULT_SSH_PORT
        if not remainder.startswith(":"):
            raise TargetParseError("malformed SSH IPv6 target literal")
        return host, _parse_port(remainder[1:])
    if cleaned.count(":") == 1:
        host, _, raw_port = cleaned.partition(":")
        if not host:
            raise TargetParseError("SSH target host is empty")
        return host, _parse_port(raw_port)
    _reject_ambiguous_unbracketed_ipv6(cleaned)
    return cleaned, DEFAULT_SSH_PORT
