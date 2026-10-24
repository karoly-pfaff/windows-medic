"""The monitoring supervisor.

Three sequential asyncio loops run under one supervisor: a cheap system sampler, a slower
process sampler whose cadence follows the adaptive sampling state, and a periodic health
log. Each loop performs one iteration at a time and then waits, so a slow iteration delays
the next one and is counted as an overrun; it never spawns a second copy of itself.

A failing iteration is logged with context and counted; the loop continues. Blocking OS
reads are offloaded from the event loop thread.
"""

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from windows_medic.application.observability import log_event
from windows_medic.application.ports.clock import Clock
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.ports.system_reader import SystemReader
from windows_medic.domain.errors import ObservationError
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason
from windows_medic.domain.models.samples import ProcessSnapshot
from windows_medic.domain.policies.adaptive_sampling import (
    AdaptivePolicy,
    SamplingMode,
    SamplingState,
    advance,
)
from windows_medic.domain.policies.pressure import PressureThresholds, instant_pressure
from windows_medic.domain.policies.rates import process_cpu_percent, system_cpu_percent
from windows_medic_agent.evidence import RollingEvidence
from windows_medic_agent.incident_engine import IncidentEngine

if TYPE_CHECKING:
    from windows_medic.domain.models.process import ProcessObservation

_logger = logging.getLogger(__name__)

# A loop that overran its interval yields at least this long so it can never spin.
MIN_PAUSE_SECONDS = 0.05


class RunBlocking(Protocol):
    """Runs a blocking call off the event loop thread (``asyncio.to_thread`` by default)."""

    def __call__[T](self, fn: Callable[[], T], /) -> Awaitable[T]: ...


@dataclass(frozen=True, slots=True)
class SamplingIntervals:
    system_seconds: float
    process_seconds: float
    escalated_process_seconds: float

    def __post_init__(self) -> None:
        for name in ("system_seconds", "process_seconds", "escalated_process_seconds"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True, slots=True)
class AgentHealth:
    """Self-observation of the agent, for logs and later soak acceptance."""

    started_at: datetime
    uptime_seconds: float
    mode: SamplingMode
    system_sample_count: int
    process_snapshot_count: int
    system_samples_held: int
    process_snapshots_held: int
    system_failures: int
    process_failures: int
    overruns: int
    last_system_sample_seconds: float | None
    max_system_sample_seconds: float
    last_process_sample_seconds: float | None
    max_process_sample_seconds: float
    self_cpu_percent: Metric[float]
    self_working_set_bytes: Metric[int]
    incidents_opened: int
    incidents_live: int
    incident_persist_failures: int


@dataclass(frozen=True, slots=True)
class _LoopStats:
    count: int = 0
    failures: int = 0
    last_seconds: float | None = None
    max_seconds: float = 0.0


class Monitor:
    """Runs the samplers until asked to stop; exposes :meth:`health` at any time."""

    def __init__(
        self,
        *,
        system_reader: SystemReader,
        process_reader: ProcessReader,
        clock: Clock,
        evidence: RollingEvidence,
        intervals: SamplingIntervals,
        thresholds: PressureThresholds,
        adaptive: AdaptivePolicy,
        own_pid: int,
        health_log_interval_seconds: float,
        incident_engine: IncidentEngine | None = None,
        run_blocking: RunBlocking = asyncio.to_thread,
    ) -> None:
        self._system_reader = system_reader
        self._process_reader = process_reader
        self._clock = clock
        self._evidence = evidence
        self._intervals = intervals
        self._thresholds = thresholds
        self._adaptive = adaptive
        self._own_pid = own_pid
        self._health_interval = health_log_interval_seconds
        self._incidents = incident_engine
        self._run_blocking = run_blocking

        self._started_at = clock.now()
        self._state = SamplingState.initial(self._started_at)
        self._cadence_changed = asyncio.Event()
        self._system = _LoopStats()
        self._processes = _LoopStats()
        self._overruns = 0
        self._previous_self: ProcessObservation | None = None
        self._self_cpu: Metric[float] = Unavailable(UnavailableReason.NO_BASELINE)
        self._self_working_set: Metric[int] = Unavailable(UnavailableReason.NO_BASELINE)

    @property
    def intervals(self) -> SamplingIntervals:
        return self._intervals

    @property
    def thresholds(self) -> PressureThresholds:
        return self._thresholds

    @property
    def adaptive(self) -> AdaptivePolicy:
        return self._adaptive

    @property
    def incident_engine(self) -> IncidentEngine | None:
        return self._incidents

    async def run(self, stop: asyncio.Event) -> None:
        """Run all loops until *stop* is set. Returns after every loop has finished."""
        log_event(_logger, "agent.monitor.started", started_at=self._started_at)
        if self._incidents is not None:
            self._incidents.interrupt_orphans()
        try:
            async with asyncio.TaskGroup() as group:
                group.create_task(
                    self._loop("system", self._sample_system, self._system_interval, stop)
                )
                group.create_task(
                    self._loop(
                        "process",
                        self._sample_processes,
                        self._process_interval,
                        stop,
                        wake=self._cadence_changed,
                    )
                )
                group.create_task(
                    self._loop("health", self._log_health, self._health_log_interval, stop)
                )
        finally:
            if self._incidents is not None:
                self._incidents.interrupt_live(self._clock.now())
        self._log_health_event("agent.monitor.stopped")

    def health(self) -> AgentHealth:
        return AgentHealth(
            started_at=self._started_at,
            uptime_seconds=(self._clock.now() - self._started_at).total_seconds(),
            mode=self._state.mode,
            system_sample_count=self._system.count,
            process_snapshot_count=self._processes.count,
            system_samples_held=len(self._evidence.system),
            process_snapshots_held=len(self._evidence.processes),
            system_failures=self._system.failures,
            process_failures=self._processes.failures,
            overruns=self._overruns,
            last_system_sample_seconds=self._system.last_seconds,
            max_system_sample_seconds=self._system.max_seconds,
            last_process_sample_seconds=self._processes.last_seconds,
            max_process_sample_seconds=self._processes.max_seconds,
            self_cpu_percent=self._self_cpu,
            self_working_set_bytes=self._self_working_set,
            incidents_opened=0 if self._incidents is None else self._incidents.opened_count,
            incidents_live=0 if self._incidents is None else self._incidents.live_count,
            incident_persist_failures=(
                0 if self._incidents is None else self._incidents.persist_failures
            ),
        )

    # -- loops ---------------------------------------------------------------------------

    async def _loop(
        self,
        name: str,
        action: Callable[[], Awaitable[None]],
        interval: Callable[[], float],
        stop: asyncio.Event,
        *,
        wake: asyncio.Event | None = None,
    ) -> None:
        """One iteration at a time; *wake* cuts the wait short (used on cadence changes)."""
        while not stop.is_set():
            if wake is not None:
                wake.clear()
            started = time.perf_counter()
            await self._supervised(name, action)
            elapsed = time.perf_counter() - started
            budget = interval()
            if elapsed > budget:
                self._overruns += 1
                log_event(
                    _logger,
                    "sampler.overrun",
                    level=logging.WARNING,
                    sampler=name,
                    elapsed_seconds=round(elapsed, 3),
                    interval_seconds=budget,
                )
            pause = max(budget - elapsed, MIN_PAUSE_SECONDS if elapsed > budget else 0)
            await _pause(stop, pause, wake)

    async def _supervised(self, name: str, action: Callable[[], Awaitable[None]]) -> None:
        """Supervision point: one failing iteration degrades one sample, never the agent."""
        try:
            await action()
        except ObservationError as exc:
            self._record_failure(name)
            log_event(
                _logger, "collector.failed", level=logging.WARNING, sampler=name, error=str(exc)
            )
        except Exception:  # supervision point: logged with context and counted, never fatal
            self._record_failure(name)
            _logger.exception("collector.crashed", extra={"event_fields": {"sampler": name}})

    def _record_failure(self, name: str) -> None:
        if name == "system":
            self._system = replace(self._system, failures=self._system.failures + 1)
        elif name == "process":
            self._processes = replace(self._processes, failures=self._processes.failures + 1)

    def _system_interval(self) -> float:
        return self._intervals.system_seconds

    def _process_interval(self) -> float:
        if self._state.mode is SamplingMode.ESCALATED:
            return self._intervals.escalated_process_seconds
        return self._intervals.process_seconds

    def _health_log_interval(self) -> float:
        return self._health_interval

    # -- actions -------------------------------------------------------------------------

    async def _sample_system(self) -> None:
        started = time.perf_counter()
        previous = self._evidence.system.latest()
        observation = await self._run_blocking(self._system_reader.snapshot)
        self._evidence.record_system(observation)
        self._system = _timed(self._system, time.perf_counter() - started)

        cpu_percent: Metric[float] = Unavailable(UnavailableReason.NO_BASELINE)
        if previous is not None:
            cpu_percent = system_cpu_percent(previous.cpu_times, observation.cpu_times)
        signal = instant_pressure(cpu_percent, observation.memory, self._thresholds)
        suspect = signal.suspect
        if self._incidents is not None:
            self._incidents.observe(observation, cpu_percent)
            suspect = suspect or self._incidents.active
        next_state = advance(self._state, observation.observed_at, suspect, self._adaptive)
        if next_state.mode is not self._state.mode:
            log_event(
                _logger,
                "sampling.mode_changed",
                previous=self._state.mode.value,
                mode=next_state.mode.value,
                cpu_suspect=signal.cpu,
                memory_suspect=signal.memory,
            )
            self._cadence_changed.set()
        self._state = next_state

    async def _sample_processes(self) -> None:
        started = time.perf_counter()
        snapshot = await self._run_blocking(self._process_reader.snapshot)
        self._evidence.record_processes(snapshot)
        self._processes = _timed(self._processes, time.perf_counter() - started)
        self._update_self_metrics(snapshot)

    def _update_self_metrics(self, snapshot: ProcessSnapshot) -> None:
        current = next((p for p in snapshot.processes if p.identity.pid == self._own_pid), None)
        if current is None:
            return
        self._self_working_set = current.working_set_bytes
        previous = self._previous_self
        latest_system = self._evidence.system.latest()
        if previous is not None and previous.identity == current.identity and latest_system:
            self._self_cpu = process_cpu_percent(
                previous, current, cpu_count=latest_system.cpu_count
            )
        self._previous_self = current

    async def _log_health(self) -> None:
        if self._incidents is not None:
            self._incidents.maintain(self._clock.now())
        self._log_health_event("agent.health")

    def _log_health_event(self, event: str) -> None:
        health = self.health()
        log_event(
            _logger,
            event,
            mode=health.mode.value,
            uptime_seconds=round(health.uptime_seconds, 1),
            system_sample_count=health.system_sample_count,
            process_snapshot_count=health.process_snapshot_count,
            system_samples_held=health.system_samples_held,
            process_snapshots_held=health.process_snapshots_held,
            system_failures=health.system_failures,
            process_failures=health.process_failures,
            overruns=health.overruns,
            last_system_sample_seconds=health.last_system_sample_seconds,
            max_system_sample_seconds=round(health.max_system_sample_seconds, 4),
            last_process_sample_seconds=health.last_process_sample_seconds,
            max_process_sample_seconds=round(health.max_process_sample_seconds, 4),
            self_cpu_percent=_metric_field(health.self_cpu_percent),
            self_working_set_bytes=_metric_field(health.self_working_set_bytes),
            incidents_opened=health.incidents_opened,
            incidents_live=health.incidents_live,
            incident_persist_failures=health.incident_persist_failures,
        )


def _metric_field(metric: Metric[float] | Metric[int]) -> object:
    return f"n/a ({metric.reason.value})" if isinstance(metric, Unavailable) else metric


def _timed(stats: _LoopStats, seconds: float) -> _LoopStats:
    rounded = round(seconds, 4)
    return replace(
        stats,
        count=stats.count + 1,
        last_seconds=rounded,
        max_seconds=max(stats.max_seconds, rounded),
    )


async def _pause(stop: asyncio.Event, seconds: float, wake: asyncio.Event | None = None) -> None:
    """Wait up to *seconds*, returning early when *stop* (or *wake*) is set."""
    if seconds <= 0:
        await asyncio.sleep(0)
        return
    events = [stop] if wake is None else [stop, wake]
    waiters = [asyncio.ensure_future(event.wait()) for event in events]
    try:
        await asyncio.wait(waiters, timeout=seconds, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for waiter in waiters:
            waiter.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.gather(*waiters, return_exceptions=True)
