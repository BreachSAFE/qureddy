# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Classify an SSH offer into PQ / classical / weak posture. Pure functions."""

from __future__ import annotations

from types import MappingProxyType

# PQ hybrid KEX (substring match -- covers @openssh.com suffixes).
_PQ_HYBRID_KEX = ("mlkem768x25519", "sntrup761x25519")
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

# name -> human note, for reporting
KEX_NOTES = MappingProxyType(
    {
        "mlkem768x25519-sha256": "ML-KEM-768 + X25519 hybrid (FIPS 203)",
        "sntrup761x25519-sha512": "Streamlined NTRU Prime + X25519 hybrid",
    }
)


def pq_hybrid_kex(offer_kex: tuple[str, ...]) -> tuple[str, ...]:
    """The PQ-hybrid KEX algorithms the server offers (may be empty)."""
    return tuple(a for a in offer_kex if any(p in a for p in _PQ_HYBRID_KEX))


def weak_host_keys(offer_host_keys: tuple[str, ...]) -> tuple[str, ...]:
    """Deprecated/weak host-key algorithms offered (e.g. ssh-dss, ssh-rsa)."""
    return tuple(a for a in offer_host_keys if a in _WEAK_HOST_KEYS)


def weak_host_key_reasons(offer_host_keys: tuple[str, ...]) -> tuple[str, ...]:
    """One 'name: reason' note per weak host-key algorithm offered, for reporting."""
    return tuple(
        f"{a}: {_WEAK_HOST_KEY_NOTES[a]}" for a in offer_host_keys if a in _WEAK_HOST_KEY_NOTES
    )
