# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Target string parser and normalizer."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from qureddy.core.errors import TargetParseError
from qureddy.core.models import ScanTarget

DEFAULT_PORT = 443
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
)
MIN_PORT = 1
MAX_PORT = 65535


def parse_target(input_str: str, sni_override: str | None = None) -> ScanTarget:
    """Parse a user-supplied target string into a normalized ScanTarget.

    Args:
        input_str: User input. Accepts hostname, host:port, https URL, or IP.
        sni_override: Optional SNI override. Required for IP targets that
            need to address a specific virtual host.

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
    is_ip = _is_ip_literal(host)

    if not is_ip and not HOSTNAME_PATTERN.match(host):
        msg = f"target host is not a valid hostname or IP: {host!r}"
        raise TargetParseError(msg)

    if sni_override is not None:
        sni: str | None = sni_override
    elif is_ip:
        sni = None
    else:
        sni = host

    return ScanTarget(
        original_input=input_str,
        host=host,
        port=port,
        sni=sni,
        locator=f"tls://{host}:{port}",
    )


def _extract_host_port(cleaned: str) -> tuple[str, int]:
    """Pull (host, port) out of any of the accepted input shapes."""
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"https", "tls"}:
            msg = f"unsupported scheme {parsed.scheme!r}; expected https or tls"
            raise TargetParseError(msg)
        host = parsed.hostname
        if not host:
            raise TargetParseError("URL has no host component")
        try:
            port = parsed.port if parsed.port is not None else DEFAULT_PORT
        except ValueError as exc:
            msg = "URL contains an invalid port"
            raise TargetParseError(msg) from exc
        return host, _validate_port(port)

    if cleaned.startswith("[") and "]" in cleaned:
        return _parse_bracketed_ipv6(cleaned)

    if cleaned.count(":") == 1:
        host, _, raw_port = cleaned.partition(":")
        if not host:
            raise TargetParseError("target host is empty")
        try:
            port = int(raw_port)
        except ValueError as exc:
            msg = f"port is not an integer: {raw_port!r}"
            raise TargetParseError(msg) from exc
        return host, _validate_port(port)

    return cleaned, DEFAULT_PORT


def _parse_bracketed_ipv6(cleaned: str) -> tuple[str, int]:
    closing = cleaned.index("]")
    host = cleaned[1:closing]
    remainder = cleaned[closing + 1 :]
    if remainder == "":
        return host, DEFAULT_PORT
    if not remainder.startswith(":"):
        raise TargetParseError("malformed IPv6 target literal")
    try:
        return host, _validate_port(int(remainder[1:]))
    except ValueError as exc:
        msg = "IPv6 target has an invalid port"
        raise TargetParseError(msg) from exc


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _validate_port(port: int) -> int:
    if not MIN_PORT <= port <= MAX_PORT:
        msg = f"port out of range [1, 65535]: {port}"
        raise TargetParseError(msg)
    return port
