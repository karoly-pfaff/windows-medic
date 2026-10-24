"""Resource-hog findings: which processes materially contributed to pressure, and when.

Built from ranked contributor evidence (incident windows plus the current sample). A hog
is *material* when its largest observed share of the machine reaches the configured CPU
or memory threshold. Attribution always names the window it was measured in. A process
known only from incident evidence is explained but gets no repair candidate: it is gone.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from windows_medic.domain.models.evidence import Evidence, EvidenceKind
from windows_medic.domain.models.finding import (
    AffectedProcess,
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
    ProcessEvidenceSample,
    Severity,
)
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason, available
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.tree import DEFAULT_DESCENDANT_LIMIT, ProcessTree
from windows_medic.domain.policies.contributor_ranking import (
    ContributorEvidence,
    IncidentContribution,
)
from windows_medic.domain.policies.finding_assembly import (
    FindingLimits,
    affected_from_tree,
    label,
    mebibytes,
    percent,
)
from windows_medic.domain.policies.protection import ProtectionPolicy, classify_protection
from windows_medic.domain.policies.repair_planning import plan_termination
from windows_medic.domain.policies.risk_markers import AncestryPolicy

_HALF_THE_MACHINE = 50.0
_FULL_PERCENT = 100.0
_LABELS = {IncidentKind.CPU_PRESSURE: "CPU", IncidentKind.MEMORY_PRESSURE: "memory"}


@dataclass(frozen=True, slots=True)
class HogThresholds:
    """Share of the whole machine (0-100) from which a contribution counts as material."""

    cpu_percent: float
    memory_percent: float

    def __post_init__(self) -> None:
        if not 0 < self.cpu_percent <= _FULL_PERCENT:
            raise ValueError("cpu_percent must be within (0, 100]")
        if not 0 < self.memory_percent <= _FULL_PERCENT:
            raise ValueError("memory_percent must be within (0, 100]")

    def material(self, cpu_share: float, memory_share: float) -> bool:
        return cpu_share >= self.cpu_percent or memory_share >= self.memory_percent


def resource_hog_findings(
    ranked: Sequence[ContributorEvidence],
    *,
    incidents: Sequence[Incident],
    tree: ProcessTree,
    memory_total_bytes: int,
    thresholds: HogThresholds,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
    window: tuple[datetime, datetime],
    limits: FindingLimits,
    max_findings: int,
) -> tuple[Finding, ...]:
    """One finding per material contributor, in ranking order, at most *max_findings*."""
    if memory_total_bytes <= 0:
        raise ValueError("memory_total_bytes must be positive")
    severities = {i.id: i.severity for i in incidents}
    findings: list[Finding] = []
    for contributor in ranked:
        if len(findings) >= max_findings:
            break
        if not thresholds.material(contributor.cpu_share, contributor.memory_share):
            continue
        findings.append(
            _finding(
                contributor,
                severities=severities,
                tree=tree,
                memory_total_bytes=memory_total_bytes,
                thresholds=thresholds,
                protection=protection,
                ancestry=ancestry,
                window=window,
                limits=limits,
            )
        )
    return tuple(findings)


def _finding(
    contributor: ContributorEvidence,
    *,
    severities: dict[str, Severity],
    tree: ProcessTree,
    memory_total_bytes: int,
    thresholds: HogThresholds,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
    window: tuple[datetime, datetime],
    limits: FindingLimits,
) -> Finding:
    current = contributor.current
    present = current is not None and tree.contains(contributor.identity)
    current_material = current is not None and thresholds.material(
        current.cpu_percent if available(current.cpu_percent) else 0.0,
        _memory_share(current, memory_total_bytes),
    )
    history = contributor.incident_contributions

    factors: list[ConfidenceFactor] = []
    if history:
        factors.append(ConfidenceFactor(ConfidenceReason.INCIDENT_CONTRIBUTION, Effect.RAISES))
    if current_material:
        factors.append(ConfidenceFactor(ConfidenceReason.CURRENT_CONTRIBUTION, Effect.RAISES))
    if not history:
        factors.append(ConfidenceFactor(ConfidenceReason.SINGLE_SAMPLE_ONLY, Effect.LOWERS))
    if current is not None and not available(current.cpu_percent):
        factors.append(ConfidenceFactor(ConfidenceReason.METRICS_PARTIAL, Effect.LOWERS))

    if history and current_material:
        level = Confidence.HIGH
    elif history:
        level = Confidence.MEDIUM
    else:
        level = Confidence.LOW

    evidence = limits.bound(
        [_incident_evidence(contributor, c) for c in history]
        + ([_current_evidence(contributor, current)] if current is not None else [])
    )
    related = [severities[c.incident_id] for c in history if c.incident_id in severities]
    severity = (
        Severity.HIGH
        if contributor.dominant_share >= _HALF_THE_MACHINE or Severity.HIGH in related
        else Severity.MEDIUM
    )

    if present:
        affected = affected_from_tree(
            contributor.identity,
            tree,
            protection=protection,
            ancestry=ancestry,
            descendant_limit=DEFAULT_DESCENDANT_LIMIT,
        )
        candidates = (
            plan_termination(
                contributor.identity,
                tree,
                protection=protection,
                ancestry=ancestry,
                evidence=evidence,
            )
            if level >= Confidence.MEDIUM
            else ()
        )
    else:
        affected = _affected_from_evidence(contributor, protection, window[1])
        candidates = ()

    return Finding(
        kind=FindingKind.RESOURCE_HOG,
        severity=severity,
        confidence=ConfidenceAssessment(level, tuple(factors)),
        summary=_summary(contributor),
        window=window,
        evidence=evidence,
        affected_processes=(affected,),
        candidate_repairs=candidates,
    )


def _incident_evidence(contributor: ContributorEvidence, c: IncidentContribution) -> Evidence:
    return Evidence(
        EvidenceKind.INCIDENT_CONTRIBUTION,
        f"{_cpu_text(c.cpu_percent)}, {_working_set_text(c.working_set_bytes)} "
        f"during {_LABELS[c.kind]} pressure incident",
        value=c.cpu_percent if available(c.cpu_percent) else None,
        window=c.window,
        identity=contributor.identity,
        incident_id=c.incident_id,
    )


def _current_evidence(contributor: ContributorEvidence, current: ProcessEvidenceSample) -> Evidence:
    return Evidence(
        EvidenceKind.CURRENT_CONTRIBUTION,
        f"now {_cpu_text(current.cpu_percent)}, {_working_set_text(current.working_set_bytes)}",
        value=current.cpu_percent if available(current.cpu_percent) else None,
        identity=contributor.identity,
    )


def _affected_from_evidence(
    contributor: ContributorEvidence, protection: ProtectionPolicy, observed_at: datetime
) -> AffectedProcess:
    """Classify a process that has exited from what the incident evidence recorded."""
    gone = Unavailable(UnavailableReason.PROCESS_GONE)
    reconstructed = ProcessObservation(
        identity=contributor.identity,
        observed_at=observed_at,
        name=contributor.name,
        exe_path=contributor.exe_path,
        command_line=gone,
        parent_pid=gone,
        username=gone,
        session_id=gone,
        cpu_time_seconds=gone,
        working_set_bytes=gone,
        private_bytes=gone,
        io_read_bytes=gone,
        io_write_bytes=gone,
        thread_count=gone,
        handle_count=gone,
    )
    return AffectedProcess(
        identity=contributor.identity,
        name=contributor.name,
        exe_path=contributor.exe_path,
        present=False,
        protection=classify_protection(reconstructed, protection).level,
        risk_markers=(),
    )


def _summary(contributor: ContributorEvidence) -> str:
    count = len(contributor.incident_contributions)
    incidents_text = (
        "no incident" if count == 0 else f"{count} incident" + ("s" if count > 1 else "")
    )
    current = contributor.current
    now_text = (
        "no longer running"
        if current is None
        else f"now {_cpu_text(current.cpu_percent)}, {_memory_text(current.working_set_bytes)}"
    )
    return (
        f"{label(contributor.name)} (pid {contributor.identity.pid}): "
        f"peak {percent(contributor.cpu_share)} CPU, {percent(contributor.memory_share)} of "
        f"memory; {incidents_text}; {now_text}"
    )


def _memory_share(sample: ProcessEvidenceSample, memory_total_bytes: int) -> float:
    if not available(sample.working_set_bytes):
        return 0.0
    return sample.working_set_bytes / memory_total_bytes * 100.0


def _cpu_text(cpu: Metric[float]) -> str:
    return f"{percent(cpu)} CPU" if available(cpu) else f"CPU unavailable ({cpu.reason.value})"


def _memory_text(working_set: Metric[int]) -> str:
    if available(working_set):
        return mebibytes(working_set)
    return f"working set unavailable ({working_set.reason.value})"


def _working_set_text(working_set: Metric[int]) -> str:
    if available(working_set):
        return f"{mebibytes(working_set)} working set"
    return _memory_text(working_set)
