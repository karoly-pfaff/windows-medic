"""Findings: explainable diagnostic conclusions.

A finding says what was concluded, how severe it is, how confident the conclusion is and
*why* (every factor that raised or lowered confidence, from a closed vocabulary), backed by
the evidence items it was derived from, the exact processes it concerns and the repairs
that could address it. Confidence is never a decorative number: policies decide the level
from the factors and both are reported together.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from windows_medic.domain.models.evidence import Evidence
from windows_medic.domain.models.incident import Severity
from windows_medic.domain.models.metric import Metric
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import RepairCandidate
from windows_medic.domain.policies.protection import ProtectionLevel
from windows_medic.domain.policies.risk_markers import RiskMarker


class FindingKind(StrEnum):
    """Declared in the order findings of equal severity and confidence are reported."""

    CPU_PRESSURE = "cpu_pressure"
    MEMORY_PRESSURE = "memory_pressure"
    RESOURCE_HOG = "resource_hog"
    HUNG_GUI = "hung_gui"
    SUSPECTED_STALE_DEV_TREE = "suspected_stale_dev_tree"


class Confidence(StrEnum):
    """Ordered: ``LOW < MEDIUM < HIGH``."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANKS[self]

    def __lt__(self, other: object) -> bool:
        return self.rank < other.rank if isinstance(other, Confidence) else NotImplemented

    def __le__(self, other: object) -> bool:
        return self.rank <= other.rank if isinstance(other, Confidence) else NotImplemented

    def __gt__(self, other: object) -> bool:
        return self.rank > other.rank if isinstance(other, Confidence) else NotImplemented

    def __ge__(self, other: object) -> bool:
        return self.rank >= other.rank if isinstance(other, Confidence) else NotImplemented


_CONFIDENCE_RANKS = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


class ConfidenceReason(StrEnum):
    """Closed vocabulary of facts that raise or lower confidence."""

    SUSTAINED_INCIDENT = "sustained_incident"
    PRESSURE_ONGOING = "pressure_ongoing"
    REPEATED_INCIDENTS = "repeated_incidents"
    CURRENT_SAMPLE_CONFIRMS = "current_sample_confirms"
    SINGLE_SAMPLE_ONLY = "single_sample_only"
    INCIDENT_CONTRIBUTION = "incident_contribution"
    CURRENT_CONTRIBUTION = "current_contribution"
    METRICS_PARTIAL = "metrics_partial"
    PARENT_GONE = "parent_gone"
    PARENT_PID_REUSED = "parent_pid_reused"
    DEVELOPMENT_CLASSIFIER = "development_classifier"
    AGE_EXCEEDS_THRESHOLD = "age_exceeds_threshold"
    RECENTLY_STARTED = "recently_started"
    MULTIPLE_DEVELOPMENT_MEMBERS = "multiple_development_members"
    PROTECTED_MEMBER = "protected_member"
    HUNG_WINDOW_REPORTED = "hung_window_reported"
    OWNER_UNVERIFIED = "owner_unverified"


class Effect(StrEnum):
    RAISES = "raises"
    LOWERS = "lowers"


@dataclass(frozen=True, slots=True)
class ConfidenceFactor:
    reason: ConfidenceReason
    effect: Effect


@dataclass(frozen=True, slots=True)
class ConfidenceAssessment:
    level: Confidence
    factors: tuple[ConfidenceFactor, ...]

    @property
    def raises(self) -> tuple[ConfidenceReason, ...]:
        return tuple(f.reason for f in self.factors if f.effect is Effect.RAISES)

    @property
    def lowers(self) -> tuple[ConfidenceReason, ...]:
        return tuple(f.reason for f in self.factors if f.effect is Effect.LOWERS)


@dataclass(frozen=True, slots=True)
class AffectedProcess:
    """A process a finding concerns, with the facts that bound what may be done to it.

    ``present`` is false for a process known only from incident evidence: it has exited,
    so nothing can be done to it, but it still explains what happened.
    """

    identity: ProcessIdentity
    name: Metric[str]
    exe_path: Metric[str]
    present: bool
    protection: ProtectionLevel
    risk_markers: tuple[RiskMarker, ...]


@dataclass(frozen=True, slots=True)
class Finding:
    kind: FindingKind
    severity: Severity
    confidence: ConfidenceAssessment
    summary: str
    window: tuple[datetime, datetime]
    evidence: tuple[Evidence, ...]
    affected_processes: tuple[AffectedProcess, ...]
    candidate_repairs: tuple[RepairCandidate, ...]
