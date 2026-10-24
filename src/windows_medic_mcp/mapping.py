"""Typed application results -> MCP boundary models. Mapping only; no decisions."""

from collections.abc import Sequence

from windows_medic.application.use_cases.diagnose_slowdown import Diagnosis
from windows_medic.application.use_cases.get_system_health import (
    ProcessContribution,
    SystemHealth,
)
from windows_medic.application.use_cases.inspect_port import (
    PortInspection,
    PortOwner,
    UnresolvedOwner,
)
from windows_medic.application.use_cases.inspect_process import (
    ProcessInspection,
    RelatedProcess,
)
from windows_medic.domain.models.evidence import Evidence
from windows_medic.domain.models.finding import AffectedProcess, Finding
from windows_medic.domain.models.incident import IncidentSummary
from windows_medic.domain.models.metric import Metric, Unavailable
from windows_medic.domain.models.network import ListeningEndpoint
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.repair import MemberResult, RepairCandidate, RepairRecord
from windows_medic.domain.models.tree import ParentLink, UnresolvedParent
from windows_medic_mcp.schemas import (
    MAX_COMMAND_LINE,
    AffectedProcessOut,
    ClearPortEligibilityOut,
    CommitOut,
    ConfidenceOut,
    ContributionOut,
    DiagnosisResponse,
    EndpointOut,
    EvidenceOut,
    EvidenceSummaryOut,
    FindingOut,
    HealthResponse,
    IncidentListResponse,
    IncidentOut,
    MemberOut,
    MemoryOut,
    PortInspectionResponse,
    PortOwnerOut,
    PressureOut,
    ProcessDetailOut,
    ProcessInspectionResponse,
    ProcessRef,
    ProtectionOut,
    RelatedProcessOut,
    RepairAfterOut,
    RepairBeforeOut,
    RepairCandidateOut,
    RepairResponse,
    UnavailableValue,
    UnresolvedOwnerOut,
    UnresolvedParentOut,
    VerificationOut,
    Window,
)

_ELLIPSIS = "..."


def ref(identity: ProcessIdentity) -> ProcessRef:
    return ProcessRef(pid=identity.pid, create_time=identity.create_time)


def metric[T](value: Metric[T]) -> T | UnavailableValue:
    if isinstance(value, Unavailable):
        return UnavailableValue(unavailable=value.reason.value)
    return value


def command_line(value: Metric[tuple[str, ...]]) -> str | UnavailableValue:
    if isinstance(value, Unavailable):
        return UnavailableValue(unavailable=value.reason.value)
    joined = " ".join(value)
    if len(joined) <= MAX_COMMAND_LINE:
        return joined
    return joined[: MAX_COMMAND_LINE - len(_ELLIPSIS)] + _ELLIPSIS


# -- health ----------------------------------------------------------------------------------


def to_health(health: SystemHealth) -> HealthResponse:
    memory = health.memory
    return HealthResponse(
        observed_at=health.observed_at,
        measurement_window_seconds=health.measurement_window_seconds,
        cpu_percent=metric(health.cpu_percent),
        cpu_count=health.cpu_count,
        memory=MemoryOut(
            total_bytes=memory.total_bytes,
            available_bytes=memory.available_bytes,
            used_bytes=memory.used_bytes,
            percent_used=memory.percent_used,
        ),
        commit=(
            UnavailableValue(unavailable=health.commit.reason.value)
            if isinstance(health.commit, Unavailable)
            else CommitOut(
                limit_bytes=health.commit.limit_bytes,
                used_bytes=health.commit.used_bytes,
                percent_used=health.commit.percent_used,
            )
        ),
        process_count=health.process_count,
        disk_read_bytes_per_second=metric(health.disk_read_bytes_per_second),
        disk_write_bytes_per_second=metric(health.disk_write_bytes_per_second),
        top_cpu=[_contribution(c) for c in health.top_cpu],
        top_memory=[_contribution(c) for c in health.top_memory],
        skipped_process_count=health.skipped_process_count,
        exited_process_count=health.exited_process_count,
        started_process_count=health.started_process_count,
    )


def _contribution(c: ProcessContribution) -> ContributionOut:
    return ContributionOut(
        process=ref(c.identity),
        name=metric(c.name),
        cpu_percent=metric(c.cpu_percent),
        working_set_bytes=metric(c.working_set_bytes),
        private_bytes=metric(c.private_bytes),
    )


# -- processes and ports ---------------------------------------------------------------------


def to_process_inspection(inspection: ProcessInspection) -> ProcessInspectionResponse:
    return ProcessInspectionResponse(
        observed_at=inspection.observed_at,
        process=_detail(inspection.observation),
        parent=_parent(inspection.parent),
        ancestors=[_related(r) for r in inspection.ancestors],
        ancestors_truncated=inspection.ancestors_truncated,
        ancestry_end=inspection.ancestry_end.value,
        descendants=[_related(r) for r in inspection.descendants],
        descendants_truncated=inspection.descendants_truncated,
        protection=ProtectionOut(
            level=inspection.protection.level.value,
            reasons=[r.value for r in inspection.protection.reasons],
        ),
        risk_markers=[m.value for m in inspection.risk_markers],
    )


def to_port_inspection(inspection: PortInspection) -> PortInspectionResponse:
    return PortInspectionResponse(
        port=inspection.port,
        observed_at=inspection.observed_at,
        owners=[_owner(o) for o in inspection.owners],
        unresolved=[_unresolved_owner(u) for u in inspection.unresolved],
        truncated=inspection.truncated,
        clear_port=ClearPortEligibilityOut(
            eligible=inspection.clear_port.eligible,
            blockers=[b.value for b in inspection.clear_port.blockers],
        ),
    )


def _detail(o: ProcessObservation) -> ProcessDetailOut:
    return ProcessDetailOut(
        process=ref(o.identity),
        name=metric(o.name),
        exe_path=metric(o.exe_path),
        command_line=command_line(o.command_line),
        username=metric(o.username),
        session_id=metric(o.session_id),
        cpu_time_seconds=metric(o.cpu_time_seconds),
        working_set_bytes=metric(o.working_set_bytes),
        private_bytes=metric(o.private_bytes),
        thread_count=metric(o.thread_count),
        handle_count=metric(o.handle_count),
    )


def _parent(link: ParentLink) -> ProcessRef | UnresolvedParentOut:
    if isinstance(link, UnresolvedParent):
        return UnresolvedParentOut(parent_pid=link.parent_pid, reason=link.reason.value)
    return ref(link)


def _related(r: RelatedProcess) -> RelatedProcessOut:
    return RelatedProcessOut(
        process=ref(r.identity), name=metric(r.name), protection=r.protection.value, depth=r.depth
    )


def _endpoint(e: ListeningEndpoint) -> EndpointOut:
    return EndpointOut(
        protocol=e.protocol.value,
        family=e.family.value,
        address=e.address,
        port=e.port,
        reported_pid=e.owner_pid,
    )


def _owner(o: PortOwner) -> PortOwnerOut:
    return PortOwnerOut(
        process=ref(o.identity),
        name=metric(o.name),
        exe_path=metric(o.exe_path),
        command_line=command_line(o.command_line),
        username=metric(o.username),
        endpoints=[_endpoint(e) for e in o.endpoints],
        parent=_parent(o.parent),
        ancestors=[_related(r) for r in o.ancestors],
        ancestors_truncated=o.ancestors_truncated,
        protection=ProtectionOut(
            level=o.protection.level.value, reasons=[r.value for r in o.protection.reasons]
        ),
        risk_markers=[m.value for m in o.risk_markers],
    )


def _unresolved_owner(u: UnresolvedOwner) -> UnresolvedOwnerOut:
    return UnresolvedOwnerOut(
        endpoint=_endpoint(u.endpoint), reported_pid=u.reported_pid, reason=u.reason.value
    )


# -- incidents and diagnosis -----------------------------------------------------------------


def to_incidents(summaries: Sequence[IncidentSummary]) -> IncidentListResponse:
    return IncidentListResponse(incidents=[_incident(s) for s in summaries])


def _incident(s: IncidentSummary) -> IncidentOut:
    return IncidentOut(
        id=s.id,
        kind=s.kind.value,
        status=s.status.value,
        severity=s.severity.value,
        started_at=s.started_at,
        triggered_at=s.triggered_at,
        closed_at=s.closed_at,
        threshold=s.threshold,
        peak=s.peak,
    )


def to_diagnosis(diagnosis: Diagnosis) -> DiagnosisResponse:
    since, until = diagnosis.lookback
    evidence = diagnosis.evidence
    return DiagnosisResponse(
        observed_at=diagnosis.observed_at,
        lookback=Window(since=since, until=until),
        current=to_health(diagnosis.current),
        pressure_now=PressureOut(
            cpu=diagnosis.pressure_now.cpu, memory=diagnosis.pressure_now.memory
        ),
        incidents=[_incident(s) for s in diagnosis.incidents],
        incidents_truncated=diagnosis.incidents_truncated,
        findings=[_finding(f) for f in diagnosis.findings],
        findings_truncated=diagnosis.findings_truncated,
        evidence=EvidenceSummaryOut(
            incidents_in_window=evidence.incidents_in_window,
            incident_system_samples=evidence.incident_system_samples,
            incident_contributor_samples=evidence.incident_contributor_samples,
            processes_observed=evidence.processes_observed,
            contributors_ranked=evidence.contributors_ranked,
            hung_windows=evidence.hung_windows,
            hung_windows_unverified=evidence.hung_windows_unverified,
        ),
    )


def _finding(f: Finding) -> FindingOut:
    since, until = f.window
    return FindingOut(
        kind=f.kind.value,
        severity=f.severity.value,
        confidence=ConfidenceOut(
            level=f.confidence.level.value,
            raised_by=[r.value for r in f.confidence.raises],
            lowered_by=[r.value for r in f.confidence.lowers],
        ),
        summary=f.summary,
        window=Window(since=since, until=until),
        evidence=[_evidence(e) for e in f.evidence],
        affected_processes=[_affected(a) for a in f.affected_processes],
        candidate_repairs=[_candidate(c) for c in f.candidate_repairs],
    )


def _evidence(e: Evidence) -> EvidenceOut:
    return EvidenceOut(
        kind=e.kind.value,
        detail=e.detail,
        value=e.value,
        window=None if e.window is None else Window(since=e.window[0], until=e.window[1]),
        process=None if e.identity is None else ref(e.identity),
        incident_id=e.incident_id,
    )


def _affected(a: AffectedProcess) -> AffectedProcessOut:
    return AffectedProcessOut(
        process=ref(a.identity),
        name=metric(a.name),
        exe_path=metric(a.exe_path),
        present=a.present,
        protection=a.protection.value,
        risk_markers=[m.value for m in a.risk_markers],
    )


def _candidate(c: RepairCandidate) -> RepairCandidateOut:
    return RepairCandidateOut(
        action=c.action.value,
        target=ref(c.target),
        scope=c.scope.value,
        risk=c.risk.value,
        requires_elevation=c.requires_elevation,
        eligible=c.eligible,
        blockers=[b.value for b in c.blockers],
    )


# -- repairs ---------------------------------------------------------------------------------


def to_repair(record: RepairRecord) -> RepairResponse:
    verification = record.verification
    return RepairResponse(
        repair_id=record.id,
        action=record.action.value,
        scope=record.scope.value,
        status=record.status.value,
        rejection=None if record.rejection is None else record.rejection.value,
        before=RepairBeforeOut(
            target=None if record.target is None else ref(record.target),
            port=record.port,
            risk=None if record.risk is None else record.risk.value,
            requires_elevation=record.requires_elevation,
            requested_at=record.requested_at,
        ),
        after=RepairAfterOut(
            completed_at=record.completed_at,
            members=[_member(m) for m in record.members],
            appeared=[ref(i) for i in record.appeared],
            replacement=None if record.replacement is None else ref(record.replacement),
            verification=(
                None
                if verification is None
                else VerificationOut(
                    passed=verification.passed,
                    detail=verification.detail,
                    checked_at=verification.checked_at,
                )
            ),
        ),
    )


def _member(m: MemberResult) -> MemberOut:
    return MemberOut(
        process=ref(m.identity),
        name=metric(m.name),
        depth=m.depth,
        outcome=m.outcome.value,
        detail=m.detail,
    )
