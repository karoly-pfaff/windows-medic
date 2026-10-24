"""Incident aggregate.

An incident is a durable, explainable record of sustained pressure: what was observed
(compact, bounded evidence), when it started and was triggered, how bad it got, and how it
ended. Transitions are pure functions returning new values.
"""

import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum

from windows_medic.domain.models.metric import Metric, available
from windows_medic.domain.models.process import ProcessIdentity


class IncidentKind(StrEnum):
    CPU_PRESSURE = "cpu_pressure"
    MEMORY_PRESSURE = "memory_pressure"


class IncidentStatus(StrEnum):
    OPEN = "open"
    RECOVERING = "recovering"
    CLOSED = "closed"
    # Monitoring stopped while the incident was live (agent stopped, crashed, machine
    # rebooted); ``closed_at`` is when it was last seen, not when pressure ended.
    INTERRUPTED = "interrupted"


class Severity(StrEnum):
    """Ordered: ``LOW < MEDIUM < HIGH``. Incidents are at least medium; findings may be low."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANKS[self]

    def __lt__(self, other: object) -> bool:
        return self.rank < other.rank if isinstance(other, Severity) else NotImplemented

    def __le__(self, other: object) -> bool:
        return self.rank <= other.rank if isinstance(other, Severity) else NotImplemented

    def __gt__(self, other: object) -> bool:
        return self.rank > other.rank if isinstance(other, Severity) else NotImplemented

    def __ge__(self, other: object) -> bool:
        return self.rank >= other.rank if isinstance(other, Severity) else NotImplemented


_SEVERITY_RANKS = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}


@dataclass(frozen=True, slots=True)
class EvidenceLimits:
    max_system_samples: int
    max_contributors: int
    high_severity_after: timedelta

    def __post_init__(self) -> None:
        if self.max_system_samples < 1:
            raise ValueError("max_system_samples must be at least 1")
        if self.max_contributors < 0:
            raise ValueError("max_contributors cannot be negative")
        if self.high_severity_after <= timedelta(0):
            raise ValueError("high_severity_after must be positive")


@dataclass(frozen=True, slots=True)
class SystemEvidenceSample:
    """A compact system sample kept as incident evidence."""

    observed_at: datetime
    cpu_percent: Metric[float]
    memory_percent_used: float
    memory_available_bytes: int
    process_count: int


@dataclass(frozen=True, slots=True)
class ProcessEvidenceSample:
    """A compact process contribution kept as incident evidence."""

    identity: ProcessIdentity
    name: Metric[str]
    exe_path: Metric[str]
    command_line: Metric[str]
    cpu_percent: Metric[float]
    working_set_bytes: Metric[int]
    private_bytes: Metric[int]


@dataclass(frozen=True, slots=True)
class Incident:
    id: str
    kind: IncidentKind
    status: IncidentStatus
    severity: Severity
    started_at: datetime
    triggered_at: datetime
    recovering_since: datetime | None
    closed_at: datetime | None
    threshold: float
    peak: float
    evidence_window: tuple[datetime, datetime]
    system_evidence: tuple[SystemEvidenceSample, ...]
    contributors: tuple[ProcessEvidenceSample, ...]

    def duration(self, now: datetime) -> timedelta:
        """Wall time since pressure started, up to closure or *now*."""
        end = self.closed_at if self.closed_at is not None else now
        return end - self.started_at

    def pressure_duration(self, now: datetime) -> timedelta:
        """Time under pressure: until recovery began, else until the incident ended (an
        interruption), else *now* while still open."""
        end = self.recovering_since or self.closed_at or now
        return end - self.started_at


def new_incident_id() -> str:
    return uuid.uuid4().hex


def open_incident(
    *,
    incident_id: str,
    kind: IncidentKind,
    started_at: datetime,
    triggered_at: datetime,
    threshold: float,
    pre_trigger: tuple[SystemEvidenceSample, ...],
    contributors: tuple[ProcessEvidenceSample, ...],
    evidence_window: tuple[datetime, datetime],
    limits: EvidenceLimits,
) -> Incident:
    """Create an OPEN incident from trigger facts and the pre-trigger evidence window."""
    evidence = pre_trigger[-limits.max_system_samples :]
    figures = [f for f in (_figure(kind, s) for s in evidence) if f is not None]
    incident = Incident(
        id=incident_id,
        kind=kind,
        status=IncidentStatus.OPEN,
        severity=Severity.MEDIUM,
        started_at=started_at,
        triggered_at=triggered_at,
        recovering_since=None,
        closed_at=None,
        threshold=threshold,
        peak=max(figures, default=threshold),
        evidence_window=evidence_window,
        system_evidence=evidence,
        contributors=contributors[: limits.max_contributors],
    )
    return _reassess(incident, triggered_at, limits)


def record_system_sample(
    incident: Incident, sample: SystemEvidenceSample, limits: EvidenceLimits
) -> Incident:
    """Append evidence while the incident is live. Bounded: keeps the opening context."""
    figure = _figure(incident.kind, sample)
    peak = incident.peak if figure is None else max(incident.peak, figure)
    evidence = incident.system_evidence
    if len(evidence) < limits.max_system_samples:
        evidence = (*evidence, sample)
    return _reassess(
        replace(incident, peak=peak, system_evidence=evidence), sample.observed_at, limits
    )


def begin_recovery(incident: Incident, now: datetime) -> Incident:
    _require(incident, IncidentStatus.OPEN)
    return replace(incident, status=IncidentStatus.RECOVERING, recovering_since=now)


def reopen_incident(incident: Incident, now: datetime) -> Incident:
    _require(incident, IncidentStatus.RECOVERING)
    del now
    return replace(incident, status=IncidentStatus.OPEN, recovering_since=None)


def close_incident(incident: Incident, now: datetime, limits: EvidenceLimits) -> Incident:
    _require(incident, IncidentStatus.RECOVERING)
    closed = replace(incident, status=IncidentStatus.CLOSED, closed_at=now)
    return _reassess(closed, now, limits)


def interrupt_incident(incident: Incident, last_seen: datetime) -> Incident:
    """End a live incident whose monitoring stopped; it ends where its evidence ends."""
    if incident.status not in (IncidentStatus.OPEN, IncidentStatus.RECOVERING):
        raise ValueError(f"incident {incident.id} has status {incident.status}, expected live")
    return replace(
        incident,
        status=IncidentStatus.INTERRUPTED,
        closed_at=max(last_seen, incident.triggered_at),
    )


def _require(incident: Incident, status: IncidentStatus) -> None:
    if incident.status is not status:
        raise ValueError(f"incident {incident.id} has status {incident.status}, expected {status}")


def _reassess(incident: Incident, now: datetime, limits: EvidenceLimits) -> Incident:
    severity = (
        Severity.HIGH
        if incident.pressure_duration(now) >= limits.high_severity_after
        else Severity.MEDIUM
    )
    return incident if severity is incident.severity else replace(incident, severity=severity)


def _figure(kind: IncidentKind, sample: SystemEvidenceSample) -> float | None:
    if kind is IncidentKind.MEMORY_PRESSURE:
        return sample.memory_percent_used
    return sample.cpu_percent if available(sample.cpu_percent) else None


@dataclass(frozen=True, slots=True)
class IncidentSummary:
    """Bounded listing row: everything needed to choose an incident, without evidence."""

    id: str
    kind: IncidentKind
    status: IncidentStatus
    severity: Severity
    started_at: datetime
    triggered_at: datetime
    closed_at: datetime | None
    threshold: float
    peak: float


def summarise(incident: Incident) -> IncidentSummary:
    return IncidentSummary(
        id=incident.id,
        kind=incident.kind,
        status=incident.status,
        severity=incident.severity,
        started_at=incident.started_at,
        triggered_at=incident.triggered_at,
        closed_at=incident.closed_at,
        threshold=incident.threshold,
        peak=incident.peak,
    )
