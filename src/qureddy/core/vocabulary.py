# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Stable protocol-neutral vocabulary shared by QuReddy models and policy."""

from __future__ import annotations

from enum import Enum


class ObservationType(str, Enum):
    """Describe how a piece of evidence was obtained."""

    NEGOTIATED = "negotiated"
    OFFERED = "offered"
    OBSERVED = "observed"
    INFERRED = "inferred"
    NOT_OFFERED = "not_offered"
    NOT_TESTABLE = "not_testable"
    NO_RESPONSE = "no_response"


class Severity(str, Enum):
    """Define CycloneDX-aligned finding severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Readiness(str, Enum):
    """Define the quantum-safe readiness verdict for a scanned asset."""

    QUANTUM_VULNERABLE = "quantum_vulnerable"
    CLASSICALLY_WEAK = "classically_weak"
    TRANSITIONAL_HYBRID = "transitional_hybrid"
    QUANTUM_SAFE = "quantum_safe"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class PqcSupport(str, Enum):
    """Define observed PQ key-exchange capability independently of posture."""

    HYBRID_OBSERVED = "hybrid_observed"
    PURE_PQ_OBSERVED = "pure_pq_observed"
    CLASSICAL_ONLY_OBSERVED = "classical_only_observed"
    UNKNOWN = "unknown"
    NOT_TESTABLE = "not_testable"


class AxisStatus(str, Enum):
    """Define the stable status vocabulary for a posture axis."""

    HYBRID = "hybrid"
    PURE_PQ = "pure_pq"
    CLASSICAL = "classical"
    ACCEPTABLE = "acceptable"
    ACTION_NEEDED = "action_needed"
    UNKNOWN = "unknown"
    NOT_TESTABLE = "not_testable"
    NOT_APPLICABLE = "not_applicable"


class HndlExposure(str, Enum):
    """Define HNDL exposure independently of present-day hygiene."""

    PROTECTED = "protected"
    PROTECTED_DEFEASIBLE = "protected_defeasible"
    AT_RISK = "at_risk"
    UNKNOWN = "unknown"


class HygieneStatus(str, Enum):
    """Define present-day protocol and primitive hygiene."""

    OK = "ok"
    ACTION_NEEDED = "action_needed"
    WEAK = "weak"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    """Define confidence levels for a finding's evidence chain."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProbeRole(str, Enum):
    """Distinguish the purpose served by a TLS key-exchange probe."""

    HYBRID_READINESS = "hybrid_readiness"
    CLASSICAL_CONTROL = "classical_control"
    HYBRID_COVERAGE = "hybrid_coverage"


class FailureCategory(str, Enum):
    """Define typed reasons a scan or probe did not complete cleanly."""

    LOCAL_OPENSSL_MISSING = "local_openssl_missing"
    LOCAL_OPENSSL_BROKEN = "local_openssl_broken"
    LOCAL_OPENSSL_VERSION_UNREADABLE = "local_openssl_version_unreadable"
    LOCAL_OPENSSL_IS_LIBRESSL = "local_openssl_is_libressl"
    LOCAL_OPENSSL_TOO_OLD = "local_openssl_too_old"
    LOCAL_OPENSSL_VERSION_MISMATCH = "local_openssl_version_mismatch"
    LOCAL_OPENSSL_LACKS_GROUP = "local_openssl_lacks_group"
    LOCAL_IKE_SCAN_MISSING = "local_ike_scan_missing"
    LOCAL_IKE_SCAN_BROKEN = "local_ike_scan_broken"
    TARGET_SCAN_FAILED = "target_scan_failed"
    TARGET_CONNECT_FAILED = "target_connect_failed"
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    SNI_REQUIRED_OR_WRONG = "sni_required_or_wrong"
    MIDDLEBOX_OR_MTU_FAILURE = "middlebox_or_mtu_failure"
    PARSE_NO_GROUP = "parse_no_group"
    PARSE_AMBIGUOUS = "parse_ambiguous"
    UNEXPECTED_GROUP = "unexpected_group"
    IKE_PROBE_TIMEOUT = "ike_probe_timeout"
    IKE_OUTPUT_LIMIT = "ike_output_limit"
    IKE_OUTPUT_MALFORMED = "ike_output_malformed"


# One owner for the operator-environment categories used by policy and renderers.
LOCAL_CAPABILITY_CATEGORIES: frozenset[FailureCategory] = frozenset(
    {
        FailureCategory.LOCAL_OPENSSL_MISSING,
        FailureCategory.LOCAL_OPENSSL_BROKEN,
        FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE,
        FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL,
        FailureCategory.LOCAL_OPENSSL_TOO_OLD,
        FailureCategory.LOCAL_OPENSSL_VERSION_MISMATCH,
        FailureCategory.LOCAL_OPENSSL_LACKS_GROUP,
        FailureCategory.LOCAL_IKE_SCAN_MISSING,
        FailureCategory.LOCAL_IKE_SCAN_BROKEN,
    }
)


class OutputFormat(str, Enum):
    """Define CLI output format choices."""

    RICH = "rich"
    JSON = "json"
    CBOM = "cbom"
    JSONL = "jsonl"
