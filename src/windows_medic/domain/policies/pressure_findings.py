"""CPU and memory pressure findings.

One finding per pressure kind, built from the incidents of that kind inside the lookback
window and the current on-demand sample. Confidence follows the evidence: an incident is
pressure *measured over the configured duration* by the agent; a single sample is not.
"""

from collections.abc import Sequence
from datetime import datetime

from windows_medic.domain.models.evidence import Evidence, EvidenceKind
from windows_medic.domain.models.finding import (
    Confidence,
    ConfidenceAssessment,
    ConfidenceFactor,
    ConfidenceReason,
    Effect,
    Finding,
    FindingKind,
)
from windows_medic.domain.models.incident import (
    Incident,
    IncidentKind,
    IncidentStatus,
    Severity,
    SystemEvidenceSample,
)
from windows_medic.domain.models.metric import Metric, available
from windows_medic.domain.policies.finding_assembly import FindingLimits, percent
from windows_medic.domain.policies.pressure import PressureSignal, PressureThresholds

_LABELS = {
    IncidentKind.CPU_PRESSURE: "CPU pressure",
    IncidentKind.MEMORY_PRESSURE: "Memory pressure",
}
_FINDING_KINDS = {
    IncidentKind.CPU_PRESSURE: FindingKind.CPU_PRESSURE,
    IncidentKind.MEMORY_PRESSURE: FindingKind.MEMORY_PRESSURE,
}
# Only incidents a running agent is still tracking count as ongoing pressure.
_LIVE = frozenset({IncidentStatus.OPEN, IncidentStatus.RECOVERING})


def pressure_findings(
    incidents: Sequence[Incident],
    *,
    current: SystemEvidenceSample,
    signal: PressureSignal,
    thresholds: PressureThresholds,
    window: tuple[datetime, datetime],
    limits: FindingLimits,
) -> tuple[Finding, ...]:
    """CPU then memory; a kind with neither incidents nor current pressure yields nothing."""
    findings: list[Finding] = []
    for kind in IncidentKind:
        finding = _finding_for(
            kind,
            sorted((i for i in incidents if i.kind is kind), key=_newest_first),
            current=current,
            above_now=signal.cpu if kind is IncidentKind.CPU_PRESSURE else signal.memory,
            threshold=_threshold(kind, thresholds),
            window=window,
            limits=limits,
        )
        if finding is not None:
            findings.append(finding)
    return tuple(findings)


def _finding_for(
    kind: IncidentKind,
    incidents: list[Incident],
    *,
    current: SystemEvidenceSample,
    above_now: bool,
    threshold: float,
    window: tuple[datetime, datetime],
    limits: FindingLimits,
) -> Finding | None:
    if not incidents and not above_now:
        return None
    now_value = _current_figure(kind, current)
    ongoing = any(i.status in _LIVE for i in incidents)

    factors: list[ConfidenceFactor] = []
    if incidents:
        factors.append(ConfidenceFactor(ConfidenceReason.SUSTAINED_INCIDENT, Effect.RAISES))
    if ongoing:
        factors.append(ConfidenceFactor(ConfidenceReason.PRESSURE_ONGOING, Effect.RAISES))
    if len(incidents) > 1:
        factors.append(ConfidenceFactor(ConfidenceReason.REPEATED_INCIDENTS, Effect.RAISES))
    if incidents and above_now:
        factors.append(ConfidenceFactor(ConfidenceReason.CURRENT_SAMPLE_CONFIRMS, Effect.RAISES))
    if not incidents:
        factors.append(ConfidenceFactor(ConfidenceReason.SINGLE_SAMPLE_ONLY, Effect.LOWERS))
    if not available(now_value):
        factors.append(ConfidenceFactor(ConfidenceReason.METRICS_PARTIAL, Effect.LOWERS))

    if incidents and (ongoing or above_now):
        level = Confidence.HIGH
    elif incidents:
        level = Confidence.MEDIUM
    else:
        level = Confidence.LOW

    evidence: list[Evidence] = []
    if above_now and available(now_value):
        evidence.append(
            Evidence(
                EvidenceKind.CURRENT_PRESSURE,
                f"now {percent(now_value)} (threshold {percent(threshold)})",
                value=now_value,
            )
        )
    evidence.extend(_incident_evidence(i, window[1]) for i in incidents)

    return Finding(
        kind=_FINDING_KINDS[kind],
        severity=max((i.severity for i in incidents), default=Severity.MEDIUM),
        confidence=ConfidenceAssessment(level, tuple(factors)),
        summary=_summary(kind, incidents, threshold, now_value, ongoing),
        window=window,
        evidence=limits.bound(evidence),
        affected_processes=(),
        candidate_repairs=(),
    )


def _incident_evidence(incident: Incident, until: datetime) -> Evidence:
    state = incident.status.value
    return Evidence(
        EvidenceKind.INCIDENT,
        f"{_LABELS[incident.kind]} incident {state}: peak {percent(incident.peak)} "
        f"vs threshold {percent(incident.threshold)}, severity {incident.severity.value}",
        value=incident.peak,
        window=(incident.started_at, incident.closed_at or until),
        incident_id=incident.id,
    )


def _summary(
    kind: IncidentKind,
    incidents: list[Incident],
    threshold: float,
    now_value: Metric[float],
    ongoing: bool,
) -> str:
    label = _LABELS[kind]
    now_text = percent(now_value) if available(now_value) else "unavailable"
    if not incidents:
        return (
            f"{label}: {now_text} now (threshold {percent(threshold)}); "
            "no sustained incident recorded"
        )
    peak = max(i.peak for i in incidents)
    count = f"{len(incidents)} incident" + ("s" if len(incidents) > 1 else "")
    state = "ongoing" if ongoing else "resolved"
    return (
        f"{label}: {count}, peak {percent(peak)} (threshold {percent(threshold)}), {state}; "
        f"now {now_text}"
    )


def _threshold(kind: IncidentKind, thresholds: PressureThresholds) -> float:
    if kind is IncidentKind.CPU_PRESSURE:
        return thresholds.cpu_percent
    return thresholds.memory_percent


def _current_figure(kind: IncidentKind, current: SystemEvidenceSample) -> Metric[float]:
    if kind is IncidentKind.CPU_PRESSURE:
        return current.cpu_percent
    return current.memory_percent_used


def _newest_first(incident: Incident) -> tuple[float, str]:
    return (-incident.started_at.timestamp(), incident.id)
