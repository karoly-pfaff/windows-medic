"""Diagnose a slowdown: turn evidence into ranked, explainable findings.

Orchestration only. The use case gathers (1) the incidents that were active inside a
bounded lookback window, (2) a fresh two-sample measurement of the machine, (3) Windows'
hung-window verdicts, and hands them to pure domain policies that rank contributors over
the whole window, build findings with explicit confidence rationale and plan candidate
repairs. Everything returned is bounded by construction; nothing is executed.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from windows_medic.application.ports.clock import Clock
from windows_medic.application.ports.hung_window_reader import HungWindowReader
from windows_medic.application.ports.incident_repository import IncidentRepository
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.ports.system_reader import SystemReader
from windows_medic.application.use_cases.get_system_health import (
    HealthLimits,
    SystemHealth,
    assess_health,
    measure,
)
from windows_medic.domain.models.finding import Finding
from windows_medic.domain.models.gui import HungWindow
from windows_medic.domain.models.incident import IncidentSummary, summarise
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.samples import ProcessSnapshot
from windows_medic.domain.models.tree import build_process_tree
from windows_medic.domain.policies.contributor_ranking import rank_contributors
from windows_medic.domain.policies.evidence import contribution_samples, summarise_system
from windows_medic.domain.policies.finding_assembly import FindingLimits
from windows_medic.domain.policies.finding_ranking import rank_findings
from windows_medic.domain.policies.hung_gui import hung_gui_findings
from windows_medic.domain.policies.pressure import (
    PressureSignal,
    PressureThresholds,
    instant_pressure,
)
from windows_medic.domain.policies.pressure_findings import pressure_findings
from windows_medic.domain.policies.process_classification import DevelopmentClassifier
from windows_medic.domain.policies.protection import ProtectionPolicy
from windows_medic.domain.policies.resource_hogs import HogThresholds, resource_hog_findings
from windows_medic.domain.policies.risk_markers import AncestryPolicy
from windows_medic.domain.policies.stale_dev_trees import stale_dev_tree_findings


@dataclass(frozen=True, slots=True)
class DiagnosisPolicy:
    """Thresholds and classifiers the diagnosis reasons with. Built from settings."""

    pressure: PressureThresholds
    hogs: HogThresholds
    stale_after: timedelta
    classifier: DevelopmentClassifier
    protection: ProtectionPolicy
    ancestry: AncestryPolicy
    max_command_line: int


@dataclass(frozen=True, slots=True)
class DiagnosisLimits:
    """Bounds on the lookback and on every collection in the result."""

    default_lookback: timedelta
    max_lookback: timedelta
    max_incidents: int
    max_findings: int
    max_hogs: int
    max_stale_trees: int
    max_hung_processes: int
    max_incidents_per_contributor: int
    finding: FindingLimits
    measurement: HealthLimits

    def __post_init__(self) -> None:
        if self.default_lookback <= timedelta(0):
            raise ValueError("default_lookback must be positive")
        if self.max_lookback < self.default_lookback:
            raise ValueError("max_lookback must not be shorter than default_lookback")
        for name in (
            "max_incidents",
            "max_findings",
            "max_hogs",
            "max_stale_trees",
            "max_hung_processes",
            "max_incidents_per_contributor",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    """What the diagnosis was based on, so an empty result is explainable too."""

    incidents_in_window: int
    incident_system_samples: int
    incident_contributor_samples: int
    processes_observed: int
    contributors_ranked: int
    hung_windows: int
    hung_windows_unverified: int


@dataclass(frozen=True, slots=True)
class Diagnosis:
    """Typed result of :class:`DiagnoseSlowdown`. Bounded by construction."""

    observed_at: datetime
    lookback: tuple[datetime, datetime]
    current: SystemHealth
    pressure_now: PressureSignal
    incidents: tuple[IncidentSummary, ...]
    incidents_truncated: bool
    findings: tuple[Finding, ...]
    findings_truncated: bool
    evidence: EvidenceSummary


class DiagnoseSlowdown:
    """Explain why the machine is (or recently was) slow, from evidence."""

    def __init__(
        self,
        *,
        system_reader: SystemReader,
        process_reader: ProcessReader,
        incident_repository: IncidentRepository,
        hung_window_reader: HungWindowReader,
        clock: Clock,
        policy: DiagnosisPolicy,
        limits: DiagnosisLimits,
    ) -> None:
        self._system_reader = system_reader
        self._process_reader = process_reader
        self._incidents = incident_repository
        self._hung_windows = hung_window_reader
        self._clock = clock
        self._policy = policy
        self._limits = limits

    @property
    def limits(self) -> DiagnosisLimits:
        return self._limits

    @property
    def policy(self) -> DiagnosisPolicy:
        return self._policy

    def execute(self, lookback: timedelta | None = None) -> Diagnosis:
        """Diagnose over *lookback* (default and maximum are configured).

        Raises:
            ValueError: If *lookback* is not positive or exceeds the configured maximum (a
                boundary validation bug, not an outcome).
            IncidentStoreError: If the incident store cannot be read.
        """
        lookback = self._limits.default_lookback if lookback is None else lookback
        if lookback <= timedelta(0) or lookback > self._limits.max_lookback:
            raise ValueError(
                f"lookback must be within (0, {self._limits.max_lookback}], got {lookback}"
            )
        limits, policy = self._limits, self._policy
        since = self._clock.now() - lookback

        loaded = self._incidents.active_since(since, limit=limits.max_incidents + 1)
        incidents = loaded[: limits.max_incidents]
        measurement = measure(
            self._system_reader, self._process_reader, self._clock, limits=limits.measurement
        )
        hung = self._hung_windows.hung_windows()

        health = assess_health(measurement, limits=limits.measurement)
        after = measurement.system_after
        window = (since, after.observed_at)
        tree = build_process_tree(measurement.processes_after)
        resolved, unverified = self._attribute_windows(hung, measurement.processes_after)
        current_samples = contribution_samples(
            measurement.processes_before,
            measurement.processes_after,
            cpu_count=after.cpu_count,
            max_command_line=policy.max_command_line,
        )
        ranked = rank_contributors(
            incidents,
            current_samples,
            memory_total_bytes=after.memory.total_bytes,
            limit=limits.max_hogs,
            max_incidents_per_contributor=limits.max_incidents_per_contributor,
        )
        signal = instant_pressure(health.cpu_percent, after.memory, policy.pressure)

        findings = [
            *pressure_findings(
                incidents,
                current=summarise_system(after, health.cpu_percent),
                signal=signal,
                thresholds=policy.pressure,
                window=window,
                limits=limits.finding,
            ),
            *resource_hog_findings(
                ranked,
                incidents=incidents,
                tree=tree,
                memory_total_bytes=after.memory.total_bytes,
                thresholds=policy.hogs,
                protection=policy.protection,
                ancestry=policy.ancestry,
                window=window,
                limits=limits.finding,
                max_findings=limits.max_hogs,
            ),
            *hung_gui_findings(
                resolved,
                unverified,
                tree=tree,
                protection=policy.protection,
                ancestry=policy.ancestry,
                window=window,
                limits=limits.finding,
                max_findings=limits.max_hung_processes,
            ),
            *stale_dev_tree_findings(
                tree,
                classifier=policy.classifier,
                protection=policy.protection,
                ancestry=policy.ancestry,
                now=after.observed_at,
                stale_after=policy.stale_after,
                thresholds=policy.hogs,
                memory_total_bytes=after.memory.total_bytes,
                window=window,
                limits=limits.finding,
                max_findings=limits.max_stale_trees,
            ),
        ]
        ranked_findings, truncated = rank_findings(findings, limit=limits.max_findings)

        return Diagnosis(
            observed_at=after.observed_at,
            lookback=window,
            current=health,
            pressure_now=signal,
            incidents=tuple(summarise(i) for i in incidents),
            incidents_truncated=len(loaded) > limits.max_incidents,
            findings=ranked_findings,
            findings_truncated=truncated,
            evidence=EvidenceSummary(
                incidents_in_window=len(incidents),
                incident_system_samples=sum(len(i.system_evidence) for i in incidents),
                incident_contributor_samples=sum(len(i.contributors) for i in incidents),
                processes_observed=len(measurement.processes_after.processes),
                contributors_ranked=len(ranked),
                hung_windows=len(hung),
                hung_windows_unverified=len(unverified),
            ),
        )

    def _attribute_windows(
        self, hung: tuple[HungWindow, ...], snapshot: ProcessSnapshot
    ) -> tuple[tuple[tuple[HungWindow, ProcessIdentity], ...], tuple[HungWindow, ...]]:
        """Pin each hung window's PID to the identity it had in *snapshot*, then re-check.

        Windows names owners by PID only. A PID absent from the snapshot, or whose identity
        can no longer be observed, is reported as unverified rather than attributed to
        whatever process holds the PID now.
        """
        by_pid = {o.identity.pid: o.identity for o in snapshot.processes}
        resolved: list[tuple[HungWindow, ProcessIdentity]] = []
        unverified: list[HungWindow] = []
        confirmed: dict[ProcessIdentity, bool] = {}
        for window in hung:
            identity = by_pid.get(window.owner_pid)
            if identity is None:
                unverified.append(window)
                continue
            if identity not in confirmed:
                confirmed[identity] = self._process_reader.get(identity) is not None
            if confirmed[identity]:
                resolved.append((window, identity))
            else:
                unverified.append(window)
        return tuple(resolved), tuple(unverified)
