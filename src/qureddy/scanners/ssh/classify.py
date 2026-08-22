# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Classify an SSH offer into PQ / classical / weak posture. Pure functions."""

from __future__ import annotations

from types import MappingProxyType

# PQ-hybrid KEX, matched by substring so every classical partner + vendor suffix is
# caught. In SSH, ML-KEM / Kyber / NTRU-Prime key exchange is ALWAYS hybrid, so these
# substrings identify PQ-hybrids with no false positives. Names per the IETF
# draft-ietf-sshm-mlkem-hybrid-kex (mlkem768nistp256-sha256, mlkem1024nistp384-sha384,
# mlkem768x25519-sha256), OpenSSH (sntrup761x25519-sha512[@openssh.com]), and the legacy
# OQS/AWS round-3 Kyber hybrids (x25519-kyber-512r3-...@amazon.com,
# ecdh-nistp256-kyber-512r3-...@openssh.com). #247: the old x25519-only list misread
# non-x25519 ML-KEM hybrids (nistp256/nistp384) as quantum_vulnerable.
_PQ_HYBRID_KEX = ("mlkem", "kyber", "sntrup761")
# Weak/deprecated host-key algorithms, keyed to a justification note. Matched
# by exact name (not prefix) so the SHA-2 families rsa-sha2-256 / rsa-sha2-512
# and their cert variants stay OUT of this set -- only bare ssh-rsa signs with
# SHA-1. Each entry cites why the algorithm is weak or deprecated.
_WEAK_HOST_KEY_NOTES = MappingProxyType(
    {
        # DSA is fixed at 1024-bit and disabled by default since OpenSSH 7.0.
        "ssh-dss": "DSA host key (1024-bit, deprecated; off by default since OpenSSH 7.0)",
        "ssh-dss-cert-v01@openssh.com": "DSA certificate host key (1024-bit, deprecated)",
        # ssh-rsa signs with SHA-1 (RFC 8332); disabled by default since OpenSSH 8.8.
        "ssh-rsa": "RSA host key with SHA-1 signature (RFC 8332; off by default since OpenSSH 8.8)",
        "ssh-rsa-cert-v01@openssh.com": "RSA certificate host key with SHA-1 signature (RFC 8332)",
    }
)
_WEAK_HOST_KEYS = frozenset(_WEAK_HOST_KEY_NOTES)
# All current SSH host-key signature families are classical (no ML-DSA/SLH-DSA
# host-key type exists in OpenSSH as of this writing).
_CLASSICAL_HOST_KEY_PREFIXES = ("ssh-ed25519", "ecdsa-sha2-", "ssh-rsa", "rsa-sha2-", "ssh-dss")

# Weak/deprecated key-exchange algorithms, keyed to a justification note. Matched
# by exact name (the scanner already collects the offered KEX name-list, so this
# reads what the probe has, no new collection). ssh-audit fails/warns on these
# small-group or SHA-1 key exchanges; each entry cites why it is weak.
_WEAK_KEX_NOTES = MappingProxyType(
    {
        # 1024-bit MODP group (Oakley group 2) plus a SHA-1 hash.
        "diffie-hellman-group1-sha1": (
            "1024-bit MODP group (Oakley group 2) with SHA-1 (RFC 4253; "
            "off by default since OpenSSH 7.0)"
        ),
        # 2048-bit group but a deprecated SHA-1 hash; SHA-2 variant preferred.
        "diffie-hellman-group14-sha1": "SHA-1 key-exchange hash (RFC 8268 prefers the SHA-2 variant)",
        # Group-exchange with a SHA-1 hash; disabled by default in modern OpenSSH.
        "diffie-hellman-group-exchange-sha1": (
            "SHA-1 key-exchange hash (off by default in modern OpenSSH)"
        ),
        # 1024-bit RSA transport key with a SHA-1 hash (RFC 4432).
        "rsa1024-sha1": "1024-bit RSA transport key with SHA-1 (RFC 4432)",
    }
)
_WEAK_KEX = frozenset(_WEAK_KEX_NOTES)

# name -> human note, for reporting
KEX_NOTES = MappingProxyType(
    {
        "mlkem768x25519-sha256": "ML-KEM-768 + X25519 hybrid (FIPS 203)",
        "mlkem768nistp256-sha256": "ML-KEM-768 + ECDH P-256 hybrid (FIPS 203)",
        "mlkem1024nistp384-sha384": "ML-KEM-1024 + ECDH P-384 hybrid (FIPS 203)",
        "sntrup761x25519-sha512": "Streamlined NTRU Prime + X25519 hybrid",
    }
)


def pq_hybrid_kex(offer_kex: tuple[str, ...]) -> tuple[str, ...]:
    """The PQ-hybrid KEX algorithms the server offers (may be empty)."""
    return tuple(a for a in offer_kex if any(p in a for p in _PQ_HYBRID_KEX))


def weak_host_keys(offer_host_keys: tuple[str, ...]) -> tuple[str, ...]:
    """Deprecated/weak host-key algorithms offered (e.g. ssh-dss, ssh-rsa)."""
    return tuple(a for a in offer_host_keys if a in _WEAK_HOST_KEYS)


def weak_host_key_note(algorithm: str) -> str | None:
    """The weakness justification for one host-key algorithm, or None if not weak."""
    return _WEAK_HOST_KEY_NOTES.get(algorithm)


def weak_host_key_reasons(offer_host_keys: tuple[str, ...]) -> tuple[str, ...]:
    """One 'name: reason' note per weak host-key algorithm offered, for reporting."""
    return tuple(
        f"{a}: {_WEAK_HOST_KEY_NOTES[a]}" for a in offer_host_keys if a in _WEAK_HOST_KEY_NOTES
    )


def weak_kex(offer_kex: tuple[str, ...]) -> tuple[str, ...]:
    """Deprecated/weak key-exchange algorithms offered (e.g. diffie-hellman-group1-sha1)."""
    return tuple(a for a in offer_kex if a in _WEAK_KEX)


def weak_kex_reasons(offer_kex: tuple[str, ...]) -> tuple[str, ...]:
    """One 'name: reason' note per weak key-exchange algorithm offered, for reporting."""
    return tuple(f"{a}: {_WEAK_KEX_NOTES[a]}" for a in offer_kex if a in _WEAK_KEX)
