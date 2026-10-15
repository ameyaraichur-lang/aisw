"""Closed vocabularies. Policy outcome, task status, run state and edge basis stay separate."""

from enum import StrEnum


class PolicyOutcome(StrEnum):  # blueprint 3.1
    PASS = "PASS"  # noqa: S105 - policy outcome, not a credential
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    EXCEPTION = "EXCEPTION"


class TaskStatus(StrEnum):  # Appendix G (8 values; resolves gap G2)
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class RunState(StrEnum):  # section 7.2 + E.4 (resolves gap G7)
    DRAFT = "DRAFT"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    AUTHORIZED = "AUTHORIZED"
    PREFLIGHT = "PREFLIGHT"
    DISCOVERY = "DISCOVERY"
    ASSESSMENT_DISPATCH = "ASSESSMENT_DISPATCH"
    NORMALIZATION = "NORMALIZATION"
    POLICY_EVALUATION = "POLICY_EVALUATION"
    CORRELATION = "CORRELATION"
    ARCHITECTURE_ANALYSIS = "ARCHITECTURE_ANALYSIS"
    ASSURANCE = "ASSURANCE"
    REPORT_READY = "REPORT_READY"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    CLOSED = "CLOSED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class EdgeBasis(StrEnum):
    OBSERVED = "OBSERVED"
    CONFIGURED = "CONFIGURED"
    INFERRED = "INFERRED"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingLifecycle(StrEnum):  # section 8.1 (separate from policy outcome, gap G6)
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ACCEPTED = "ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    EXCEPTION_PENDING = "EXCEPTION_PENDING"
    IN_REMEDIATION = "IN_REMEDIATION"
    PENDING_VALIDATION = "PENDING_VALIDATION"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class ManifestStatus(StrEnum):
    DRAFT = "DRAFT"
    PREFLIGHTED = "PREFLIGHTED"
    APPROVED = "APPROVED"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"


class AssuranceVerdict(StrEnum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class RecommendationStatus(StrEnum):  # section 10.1; execution status is separate
    DRAFT = "DRAFT"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    APPROVED_FOR_PLANNING = "APPROVED_FOR_PLANNING"
    REJECTED = "REJECTED"
    IMPLEMENTED_PENDING_VALIDATION = "IMPLEMENTED_PENDING_VALIDATION"


class ProfileClass(StrEnum):
    READ_ONLY = "READ_ONLY"
    ACTIVE = "ACTIVE"  # requires explicit human approval (Agent 0)
