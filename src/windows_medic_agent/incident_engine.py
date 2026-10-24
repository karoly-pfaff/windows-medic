"""Incident engine: turns the stream of system samples into durable incidents.

Fed once per system sample by the monitor. Per pressure kind it advances a pure lifecycle
tracker; on ``OPENED`` it builds the incident from the rolling evidence (pre-trigger system
samples and the top contributors between the last two process snapshots), then keeps the
live incident updated with bounded evidence. Writes are throttled while an incident is
open and immediate on transitions; a failing write is logged, counted and retried on a
later tick, never propagated into the sampling loop.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from windows_medic.application.observability import log_event
from windows_medic.application.ports.incident_repository import IncidentRepository
from windows_medic.domain.errors import IncidentStoreError
from windows_medic.domain.models.incident import (
    EvidenceLimits,
    Incident,
    IncidentKind,
    SystemEvidenceSample,
    begin_recovery,
    close_incident,
    interrupt_incident,
    new_incident_id,
    open_incident,
    record_system_sample,
    reopen_incident,
)
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason
from windows_medic.domain.models.samples import SystemObservation
from windows_medic.domain.policies.evidence import summarise_system, top_contributors
from windows_medic.domain.policies.pressure import PressureThresholds, instant_pressure
from windows_medic.domain.policies.pressure_lifecycle import (
    LifecyclePolicy,
    Phase,
    PressureTracker,
    Transition,
)
from windows_medic.domain.policies.rates import system_cpu_percent
from windows_medic_agent.evidence import RollingEvidence

_logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class IncidentPolicy:
    thresholds: PressureThresholds
    cpu_lifecycle: LifecyclePolicy
    memory_lifecycle: LifecyclePolicy
    evidence: EvidenceLimits
    pre_trigger_window: timedelta
    persist_interval: timedelta
    max_command_line: int
    retention: timedelta
    maintenance_interval: timedelta

    def lifecycle_for(self, kind: IncidentKind) -> LifecyclePolicy:
        return self.cpu_lifecycle if kind is IncidentKind.CPU_PRESSURE else self.memory_lifecycle

    def threshold_for(self, kind: IncidentKind) -> float:
        if kind is IncidentKind.CPU_PRESSURE:
            return self.thresholds.cpu_percent
        return self.thresholds.memory_percent


@dataclass(slots=True)
class _Live:
    """A live incident plus its persistence bookkeeping."""

    incident: Incident
    dirty: bool = True
    force: bool = True
    last_attempt_at: datetime | None = None


@dataclass(slots=True)
class _Kind:
    tracker: PressureTracker = field(default_factory=PressureTracker.idle)
    live: _Live | None = None


class IncidentEngine:
    def __init__(
        self,
        *,
        repository: IncidentRepository,
        evidence: RollingEvidence,
        policy: IncidentPolicy,
        ids: Callable[[], str] = new_incident_id,
    ) -> None:
        self._repository = repository
        self._evidence = evidence
        self._policy = policy
        self._ids = ids
        self._kinds = {kind: _Kind() for kind in IncidentKind}
        self._opened = 0
        self._persist_failures = 0
        self._last_maintenance: datetime | None = None

    # -- observability ---------------------------------------------------------------------

    @property
    def policy(self) -> IncidentPolicy:
        return self._policy

    @property
    def opened_count(self) -> int:
        return self._opened

    @property
    def persist_failures(self) -> int:
        return self._persist_failures

    @property
    def live_count(self) -> int:
        return sum(1 for state in self._kinds.values() if state.live is not None)

    @property
    def active(self) -> bool:
        """True while any kind is suspect, open or recovering (drives sampling escalation)."""
        return any(state.tracker.phase is not Phase.NONE for state in self._kinds.values())

    # -- ticks -----------------------------------------------------------------------------

    def observe(self, observation: SystemObservation, cpu_percent: Metric[float]) -> None:
        """Advance every pressure kind with one system sample (already in the evidence)."""
        now = observation.observed_at
        signal = instant_pressure(cpu_percent, observation.memory, self._policy.thresholds)
        sample = summarise_system(observation, cpu_percent)
        for kind, above in (
            (IncidentKind.CPU_PRESSURE, signal.cpu),
            (IncidentKind.MEMORY_PRESSURE, signal.memory),
        ):
            state = self._kinds[kind]
            state.tracker, transition = state.tracker.advance(
                now, above=above, policy=self._policy.lifecycle_for(kind)
            )
            self._apply(kind, state, transition, sample, observation)
            self._flush(kind, state, now)

    def interrupt_orphans(self) -> None:
        """Interrupt incidents a previous run left live. Call once, before the first sample,
        while holding the agent's single-instance lease; a store failure is logged only."""
        try:
            interrupted = self._repository.interrupt_unclosed()
        except IncidentStoreError as exc:
            log_event(_logger, "incident.interrupt_failed", level=logging.WARNING, error=str(exc))
            return
        for incident_id in interrupted:
            log_event(
                _logger, "incident.interrupted", incident_id=incident_id, cause="previous_run"
            )

    def interrupt_live(self, now: datetime) -> None:
        """Monitoring stops: end every live incident at *now* and write it (best effort)."""
        for kind, state in self._kinds.items():
            live = state.live
            if live is None:
                continue
            live.incident = interrupt_incident(live.incident, now)
            live.dirty = live.force = True
            log_event(
                _logger, "incident.interrupted", incident_id=live.incident.id, cause="agent_stopped"
            )
            self._flush(kind, state, now)

    def maintain(self, now: datetime) -> None:
        """Run retention cleanup once per maintenance interval; failures are logged only."""
        due = (
            self._last_maintenance is None
            or now - self._last_maintenance >= self._policy.maintenance_interval
        )
        if not due:
            return
        self._last_maintenance = now
        cutoff = now - self._policy.retention
        try:
            removed = self._repository.purge_older_than(cutoff)
        except IncidentStoreError as exc:
            log_event(
                _logger,
                "incident.maintenance_failed",
                level=logging.WARNING,
                cutoff=cutoff,
                error=str(exc),
            )
            return
        log_event(_logger, "incident.maintenance", cutoff=cutoff, removed=removed)

    # -- transitions -----------------------------------------------------------------------

    def _apply(
        self,
        kind: IncidentKind,
        state: _Kind,
        transition: Transition,
        sample: SystemEvidenceSample,
        observation: SystemObservation,
    ) -> None:
        now = observation.observed_at
        if transition is Transition.OPENED:
            state.live = _Live(self._open(kind, state.tracker, now, observation))
            self._opened += 1
            log_event(
                _logger,
                "incident.opened",
                incident_id=state.live.incident.id,
                kind=kind.value,
                started_at=state.live.incident.started_at,
                peak=state.live.incident.peak,
            )
            return
        if transition in (Transition.SUSPECT_STARTED, Transition.SUSPECT_CLEARED):
            log_event(_logger, f"incident.{transition.value}", kind=kind.value, at=now)
            return
        if state.live is None:
            return
        incident = state.live.incident
        if transition is Transition.RECOVERING:
            incident = begin_recovery(incident, now)
        elif transition is Transition.REOPENED:
            incident = reopen_incident(incident, now)
        elif transition is Transition.CLOSED:
            incident = close_incident(incident, now, self._policy.evidence)
        else:
            incident = record_system_sample(incident, sample, self._policy.evidence)
        if transition is not Transition.NONE:
            log_event(
                _logger,
                f"incident.{transition.value}",
                incident_id=incident.id,
                kind=kind.value,
                status=incident.status.value,
                severity=incident.severity.value,
            )
        state.live.incident = incident
        state.live.dirty = True
        if transition is not Transition.NONE:
            state.live.force = True  # transitions are written immediately

    def _open(
        self,
        kind: IncidentKind,
        tracker: PressureTracker,
        now: datetime,
        observation: SystemObservation,
    ) -> Incident:
        window_start = now - self._policy.pre_trigger_window
        snapshots = self._evidence.processes.items()
        before = snapshots[-2] if len(snapshots) >= 2 else None  # noqa: PLR2004
        after = snapshots[-1] if snapshots else None
        contributors = (
            ()
            if after is None
            else top_contributors(
                before,
                after,
                cpu_count=observation.cpu_count,
                limit=self._policy.evidence.max_contributors,
                max_command_line=self._policy.max_command_line,
            )
        )
        return open_incident(
            incident_id=self._ids(),
            kind=kind,
            started_at=tracker.since if tracker.since is not None else now,
            triggered_at=now,
            threshold=self._policy.threshold_for(kind),
            pre_trigger=self._pre_trigger(window_start),
            contributors=contributors,
            evidence_window=(window_start, now),
            limits=self._policy.evidence,
        )

    def _pre_trigger(self, window_start: datetime) -> tuple[SystemEvidenceSample, ...]:
        """System samples in the window, with CPU % recomputed between consecutive samples."""
        samples: list[SystemEvidenceSample] = []
        previous: SystemObservation | None = None
        for observation in self._evidence.system.items():
            if observation.observed_at >= window_start:
                cpu: Metric[float] = (
                    Unavailable(UnavailableReason.NO_BASELINE)
                    if previous is None
                    else system_cpu_percent(previous.cpu_times, observation.cpu_times)
                )
                samples.append(summarise_system(observation, cpu))
            previous = observation
        return tuple(samples)

    # -- persistence -----------------------------------------------------------------------

    def _flush(self, kind: IncidentKind, state: _Kind, now: datetime) -> None:
        """Write the live incident: immediately after a transition, else at most once per
        persist interval (which also paces retries after a failed write)."""
        live = state.live
        if live is None or not live.dirty:
            return
        paced = (
            live.last_attempt_at is not None
            and now - live.last_attempt_at < self._policy.persist_interval
        )
        if paced and not live.force:
            return
        live.force = False
        live.last_attempt_at = now
        try:
            self._repository.save(live.incident)
        except IncidentStoreError as exc:
            self._persist_failures += 1
            log_event(
                _logger,
                "incident.persist_failed",
                level=logging.WARNING,
                incident_id=live.incident.id,
                kind=kind.value,
                error=str(exc),
            )
            return
        live.dirty = False
        if live.incident.closed_at is not None:
            state.live = None
