"""MCP boundary models: the exact, bounded JSON shapes tools return.

Pydantic is used here, at the boundary, and nowhere inside the domain. Every collection
in these models is bounded by the use case that produced it; every metric that could not
be observed is an explicit ``{"unavailable": reason}`` object, never a fake number.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_COMMAND_LINE = 512


class _Out(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class UnavailableValue(_Out):
    unavailable: str = Field(description="why the value could not be observed")


class ProcessRef(_Out):
    """An exact process identity: a PID is never enough on Windows (PIDs are reused)."""

    pid: int
    create_time: datetime


class Window(_Out):
    since: datetime
    until: datetime


# -- health ----------------------------------------------------------------------------------


class MemoryOut(_Out):
    total_bytes: int
    available_bytes: int
    used_bytes: int
    percent_used: float


class CommitOut(_Out):
    limit_bytes: int
    used_bytes: int
    percent_used: float


class ContributionOut(_Out):
    process: ProcessRef
    name: str | UnavailableValue
    cpu_percent: float | UnavailableValue
    working_set_bytes: int | UnavailableValue
    private_bytes: int | UnavailableValue


class HealthResponse(_Out):
    observed_at: datetime
    measurement_window_seconds: float
    cpu_percent: float | UnavailableValue
    cpu_count: int
    memory: MemoryOut
    commit: CommitOut | UnavailableValue
    process_count: int
    disk_read_bytes_per_second: float | UnavailableValue
    disk_write_bytes_per_second: float | UnavailableValue
    top_cpu: list[ContributionOut]
    top_memory: list[ContributionOut]
    skipped_process_count: int
    exited_process_count: int
    started_process_count: int


# -- processes and ports ---------------------------------------------------------------------


class UnresolvedParentOut(_Out):
    parent_pid: int | None
    reason: str


class RelatedProcessOut(_Out):
    process: ProcessRef
    name: str | UnavailableValue
    protection: str
    depth: int


class ProtectionOut(_Out):
    level: str
    reasons: list[str]


class ProcessDetailOut(_Out):
    process: ProcessRef
    name: str | UnavailableValue
    exe_path: str | UnavailableValue
    command_line: str | UnavailableValue = Field(
        description=f"joined and truncated to {MAX_COMMAND_LINE} characters"
    )
    username: str | UnavailableValue
    session_id: int | UnavailableValue
    cpu_time_seconds: float | UnavailableValue
    working_set_bytes: int | UnavailableValue
    private_bytes: int | UnavailableValue
    thread_count: int | UnavailableValue
    handle_count: int | UnavailableValue


class ProcessInspectionResponse(_Out):
    observed_at: datetime
    process: ProcessDetailOut
    parent: ProcessRef | UnresolvedParentOut
    ancestors: list[RelatedProcessOut] = Field(description="nearest first")
    ancestors_truncated: bool
    ancestry_end: str
    descendants: list[RelatedProcessOut]
    descendants_truncated: bool
    protection: ProtectionOut
    risk_markers: list[str]


class EndpointOut(_Out):
    protocol: str
    family: str
    address: str
    port: int
    reported_pid: int | None


class PortOwnerOut(_Out):
    process: ProcessRef
    name: str | UnavailableValue
    exe_path: str | UnavailableValue
    command_line: str | UnavailableValue
    username: str | UnavailableValue
    endpoints: list[EndpointOut]
    parent: ProcessRef | UnresolvedParentOut
    ancestors: list[RelatedProcessOut]
    ancestors_truncated: bool
    protection: ProtectionOut
    risk_markers: list[str]


class UnresolvedOwnerOut(_Out):
    endpoint: EndpointOut
    reported_pid: int | None
    reason: str


class ClearPortEligibilityOut(_Out):
    eligible: bool
    blockers: list[str]


class PortInspectionResponse(_Out):
    port: int
    observed_at: datetime
    owners: list[PortOwnerOut]
    unresolved: list[UnresolvedOwnerOut]
    truncated: bool
    clear_port: ClearPortEligibilityOut


# -- incidents and diagnosis -----------------------------------------------------------------


class IncidentOut(_Out):
    id: str
    kind: str
    status: str
    severity: str
    started_at: datetime
    triggered_at: datetime
    closed_at: datetime | None
    threshold: float
    peak: float


class IncidentListResponse(_Out):
    incidents: list[IncidentOut] = Field(description="newest first")


class ConfidenceOut(_Out):
    level: str
    raised_by: list[str]
    lowered_by: list[str]


class EvidenceOut(_Out):
    kind: str
    detail: str
    value: float | None
    window: Window | None
    process: ProcessRef | None
    incident_id: str | None


class AffectedProcessOut(_Out):
    process: ProcessRef
    name: str | UnavailableValue
    exe_path: str | UnavailableValue
    present: bool
    protection: str
    risk_markers: list[str]


class RepairCandidateOut(_Out):
    action: str
    target: ProcessRef
    scope: str
    risk: str
    requires_elevation: bool
    eligible: bool
    blockers: list[str]


class FindingOut(_Out):
    kind: str
    severity: str
    confidence: ConfidenceOut
    summary: str
    window: Window
    evidence: list[EvidenceOut]
    affected_processes: list[AffectedProcessOut]
    candidate_repairs: list[RepairCandidateOut]


class PressureOut(_Out):
    cpu: bool
    memory: bool


class EvidenceSummaryOut(_Out):
    incidents_in_window: int
    incident_system_samples: int
    incident_contributor_samples: int
    processes_observed: int
    contributors_ranked: int
    hung_windows: int
    hung_windows_unverified: int


class DiagnosisResponse(_Out):
    observed_at: datetime
    lookback: Window
    current: HealthResponse
    pressure_now: PressureOut
    incidents: list[IncidentOut]
    incidents_truncated: bool
    findings: list[FindingOut] = Field(description="ranked: severity, confidence, kind")
    findings_truncated: bool
    evidence: EvidenceSummaryOut


# -- repairs (mutations) ---------------------------------------------------------------------


class MemberOut(_Out):
    process: ProcessRef
    name: str | UnavailableValue
    depth: int
    outcome: str
    detail: str | None


class VerificationOut(_Out):
    passed: bool
    detail: str
    checked_at: datetime


class RepairBeforeOut(_Out):
    target: ProcessRef | None
    port: int | None
    risk: str | None
    requires_elevation: bool
    requested_at: datetime


class RepairAfterOut(_Out):
    completed_at: datetime | None
    members: list[MemberOut]
    appeared: list[ProcessRef] = Field(
        description="processes that appeared under planned members after the plan (not targeted)"
    )
    replacement: ProcessRef | None
    verification: VerificationOut | None


class RepairResponse(_Out):
    """The structured before/action/after record of one mutation attempt."""

    mutation: Literal[True] = True
    repair_id: str
    action: str
    scope: str
    status: str
    rejection: str | None
    before: RepairBeforeOut
    after: RepairAfterOut
