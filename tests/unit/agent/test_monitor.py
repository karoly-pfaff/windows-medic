"""Monitor: sequential samplers under supervision, bounded evidence, adaptive cadence."""

import asyncio
import logging
import threading
import time
from collections.abc import Callable
from datetime import timedelta

import pytest

from tests.builders import GIB, incident, process, process_snapshot, system
from tests.fakes import FakeIncidentRepository
from windows_medic.domain.errors import ObservationError
from windows_medic.domain.models.incident import EvidenceLimits, IncidentKind, IncidentStatus
from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.samples import ProcessSnapshot, SystemObservation
from windows_medic.domain.policies.adaptive_sampling import AdaptivePolicy, SamplingMode
from windows_medic.domain.policies.pressure import PressureThresholds
from windows_medic.domain.policies.pressure_lifecycle import LifecyclePolicy
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic_agent.evidence import EvidenceRetention, RollingEvidence
from windows_medic_agent.incident_engine import IncidentEngine, IncidentPolicy
from windows_medic_agent.monitor import (
    AgentHealth,
    Monitor,
    SamplingIntervals,
    _LoopStats,
    _pause,
    _timed,
)

OWN_PID = 4242
CLOCK = SystemClock()
THRESHOLDS = PressureThresholds(
    cpu_percent=90.0, memory_percent=90.0, memory_available_floor_bytes=GIB
)
ADAPTIVE = AdaptivePolicy(escalation_max=timedelta(seconds=30), cooldown=timedelta(seconds=30))
FAST = SamplingIntervals(system_seconds=0.01, process_seconds=0.03, escalated_process_seconds=0.01)


class SyntheticSystemReader:
    """Cumulative CPU counters advancing at a chosen busy share, stamped with real time."""

    def __init__(self, busy_share: float = 0.1) -> None:
        self.busy_share = busy_share
        self.calls = 0
        self._busy = 0.0
        self._total = 0.0
        self.failures: set[int] = set()

    def snapshot(self) -> SystemObservation:
        self.calls += 1
        if self.calls in self.failures:
            raise ObservationError("synthetic system failure")
        self._total += 1.0
        self._busy += self.busy_share
        return system(observed_at=CLOCK.now(), busy_seconds=self._busy, total_seconds=self._total)


class SyntheticProcessReader:
    """One synthetic 'own' process whose CPU time advances 0.5 s per call."""

    def __init__(self, *, block_seconds: float = 0.0) -> None:
        self.calls = 0
        self.active = 0
        self.max_active = 0
        self.failures: dict[int, Exception] = {}
        self._block = block_seconds
        self._cpu = 0.0
        self._lock = threading.Lock()

    def snapshot(self) -> ProcessSnapshot:
        with self._lock:
            self.calls += 1
            call = self.calls
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if call in self.failures:
                raise self.failures[call]
            if self._block:
                time.sleep(self._block)
            self._cpu += 0.5
            return process_snapshot(
                process(OWN_PID, observed_at=CLOCK.now(), cpu_time_seconds=self._cpu),
                process(7, observed_at=CLOCK.now(), name="other.exe"),
                observed_at=CLOCK.now(),
            )
        finally:
            with self._lock:
                self.active -= 1

    def get(self, identity: ProcessIdentity) -> ProcessObservation | None:
        return None


def evidence(max_system: int = 5, max_processes: int = 3) -> RollingEvidence:
    return RollingEvidence(
        EvidenceRetention(
            window=timedelta(minutes=30),
            max_system_samples=max_system,
            max_process_snapshots=max_processes,
        )
    )


def monitor(
    *,
    system_reader: SyntheticSystemReader | None = None,
    process_reader: SyntheticProcessReader | None = None,
    store: RollingEvidence | None = None,
    intervals: SamplingIntervals = FAST,
    health_log_interval: float = 0.05,
) -> Monitor:
    return Monitor(
        system_reader=system_reader or SyntheticSystemReader(),
        process_reader=process_reader or SyntheticProcessReader(),
        clock=CLOCK,
        evidence=store or evidence(),
        intervals=intervals,
        thresholds=THRESHOLDS,
        adaptive=ADAPTIVE,
        own_pid=OWN_PID,
        health_log_interval_seconds=health_log_interval,
    )


def run_until(
    under_test: Monitor, condition: Callable[[AgentHealth], bool], deadline: float = 5.0
) -> AgentHealth:
    """Run the monitor until *condition* holds (bounded), then stop it and return health."""

    async def drive() -> AgentHealth:
        stop = asyncio.Event()
        task = asyncio.create_task(under_test.run(stop))
        started = time.perf_counter()
        try:
            while not condition(under_test.health()):
                if time.perf_counter() - started > deadline:
                    pytest.fail(f"condition not met within {deadline}s: {under_test.health()}")
                await asyncio.sleep(0.005)
            return under_test.health()
        finally:
            stop.set()
            await asyncio.wait_for(task, timeout=5)

    return asyncio.run(drive())


class TestSampling:
    def test_collects_both_kinds_of_samples_into_bounded_evidence(self) -> None:
        store = evidence(max_system=5, max_processes=3)
        under_test = monitor(store=store)

        health = run_until(
            under_test, lambda h: h.system_sample_count >= 12 and h.process_snapshot_count >= 6
        )

        assert len(store.system) <= 5
        assert len(store.processes) <= 3
        assert health.system_samples_held == len(store.system)
        assert health.process_snapshots_held == len(store.processes)
        assert health.last_system_sample_seconds is not None
        assert health.max_process_sample_seconds >= (health.last_process_sample_seconds or 0)

    def test_stop_returns_promptly(self) -> None:
        under_test = monitor()

        async def drive() -> float:
            stop = asyncio.Event()
            task = asyncio.create_task(under_test.run(stop))
            await asyncio.sleep(0.05)
            started = time.perf_counter()
            stop.set()
            await asyncio.wait_for(task, timeout=5)
            return time.perf_counter() - started

        assert asyncio.run(drive()) < 1.0

    def test_uptime_and_start_time_are_reported(self) -> None:
        health = run_until(monitor(), lambda h: h.system_sample_count >= 2)

        assert health.started_at.tzinfo is not None
        assert health.uptime_seconds >= 0.0


class TestFailureContainment:
    def test_one_failing_process_read_does_not_stop_subsequent_sampling(self) -> None:
        reader = SyntheticProcessReader()
        reader.failures[2] = ObservationError("enumeration failed")

        health = run_until(monitor(process_reader=reader), lambda h: h.process_snapshot_count >= 4)

        assert health.process_failures == 1
        assert reader.calls >= 5

    def test_unexpected_collector_crash_is_contained_and_counted(self) -> None:
        reader = SyntheticProcessReader()
        reader.failures[1] = RuntimeError("bug in collector")

        health = run_until(monitor(process_reader=reader), lambda h: h.process_snapshot_count >= 3)

        assert health.process_failures == 1

    def test_system_collector_failures_are_counted_separately(self) -> None:
        reader = SyntheticSystemReader()
        reader.failures = {1, 2}

        health = run_until(monitor(system_reader=reader), lambda h: h.system_sample_count >= 3)

        assert health.system_failures == 2
        assert health.process_failures == 0

    def test_failure_events_are_logged_with_context(self, caplog: pytest.LogCaptureFixture) -> None:
        reader = SyntheticProcessReader()
        reader.failures[1] = ObservationError("enumeration failed")

        with caplog.at_level(logging.WARNING, logger="windows_medic_agent.monitor"):
            run_until(monitor(process_reader=reader), lambda h: h.process_snapshot_count >= 2)

        events = [record.getMessage() for record in caplog.records]
        assert "collector.failed" in events


class TestNoOverlap:
    def test_a_slow_iteration_delays_the_next_instead_of_overlapping(self) -> None:
        reader = SyntheticProcessReader(block_seconds=0.05)
        intervals = SamplingIntervals(
            system_seconds=0.01, process_seconds=0.01, escalated_process_seconds=0.01
        )

        health = run_until(
            monitor(process_reader=reader, intervals=intervals),
            lambda h: h.process_snapshot_count >= 3,
        )

        assert reader.max_active == 1
        assert health.overruns >= 1


class TestAdaptiveCadence:
    def test_pressure_escalates_process_sampling(self) -> None:
        slow_normal = SamplingIntervals(
            system_seconds=0.01, process_seconds=5.0, escalated_process_seconds=0.01
        )
        under_test = monitor(
            system_reader=SyntheticSystemReader(busy_share=1.0), intervals=slow_normal
        )

        # With a 5 s normal cadence, several snapshots within the deadline prove the
        # escalated (10 ms) cadence is in effect.
        health = run_until(
            under_test,
            lambda h: h.mode is SamplingMode.ESCALATED and h.process_snapshot_count >= 4,
        )

        assert health.mode is SamplingMode.ESCALATED
        assert health.process_snapshot_count >= 4

    def test_calm_system_stays_normal(self) -> None:
        health = run_until(
            monitor(system_reader=SyntheticSystemReader(busy_share=0.1)),
            lambda h: h.system_sample_count >= 5,
        )

        assert health.mode is SamplingMode.NORMAL

    def test_mode_changes_are_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.INFO, logger="windows_medic_agent.monitor"):
            run_until(
                monitor(system_reader=SyntheticSystemReader(busy_share=1.0)),
                lambda h: h.mode is SamplingMode.ESCALATED,
            )

        assert "sampling.mode_changed" in [r.getMessage() for r in caplog.records]


class TestSelfOverhead:
    def test_self_cpu_and_memory_come_from_the_agents_own_entry(self) -> None:
        health = run_until(monitor(), lambda h: available(h.self_cpu_percent))

        assert available(health.self_cpu_percent)
        assert 0.0 <= health.self_cpu_percent <= 100.0
        assert available(health.self_working_set_bytes)
        assert health.self_working_set_bytes > 0

    def test_health_is_logged_periodically(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.INFO, logger="windows_medic_agent.monitor"):
            run_until(monitor(health_log_interval=0.02), lambda h: h.system_sample_count >= 10)

        health_events = [r for r in caplog.records if r.getMessage() == "agent.health"]
        assert len(health_events) >= 2
        fields = getattr(health_events[-1], "event_fields", {})
        assert {"mode", "system_samples_held", "self_cpu_percent", "overruns"} <= set(fields)


class TestValidation:
    def test_intervals_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="system_seconds"):
            SamplingIntervals(system_seconds=0, process_seconds=1, escalated_process_seconds=1)

    def test_run_blocking_hook_is_used_for_os_calls(self) -> None:
        offloaded: list[str] = []

        async def run_blocking[T](fn: Callable[[], T]) -> T:
            offloaded.append(fn.__name__)
            return fn()

        under_test = Monitor(
            system_reader=SyntheticSystemReader(),
            process_reader=SyntheticProcessReader(),
            clock=CLOCK,
            evidence=evidence(),
            intervals=FAST,
            thresholds=THRESHOLDS,
            adaptive=ADAPTIVE,
            own_pid=OWN_PID,
            health_log_interval_seconds=1.0,
            run_blocking=run_blocking,
        )

        run_until(
            under_test, lambda h: h.system_sample_count >= 1 and h.process_snapshot_count >= 1
        )

        assert "snapshot" in offloaded


class TestPause:
    def test_zero_or_negative_pause_yields_without_waiting(self) -> None:
        async def drive() -> float:
            started = time.perf_counter()
            await _pause(asyncio.Event(), 0.0)
            await _pause(asyncio.Event(), -1.0)
            return time.perf_counter() - started

        assert asyncio.run(drive()) < 0.5

    def test_pause_returns_early_when_woken(self) -> None:
        async def drive() -> float:
            wake = asyncio.Event()
            asyncio.get_running_loop().call_later(0.01, wake.set)
            started = time.perf_counter()
            await _pause(asyncio.Event(), 5.0, wake)
            return time.perf_counter() - started

        assert asyncio.run(drive()) < 1.0

    def test_pause_returns_early_when_stop_is_set(self) -> None:
        async def drive() -> float:
            stop = asyncio.Event()
            asyncio.get_running_loop().call_later(0.01, stop.set)
            started = time.perf_counter()
            await _pause(stop, 5.0)
            return time.perf_counter() - started

        assert asyncio.run(drive()) < 1.0


class TestIncidentIntegration:
    def _engine(self, repository: FakeIncidentRepository) -> IncidentEngine:
        return IncidentEngine(
            repository=repository,
            evidence=evidence(),
            policy=IncidentPolicy(
                thresholds=THRESHOLDS,
                cpu_lifecycle=LifecyclePolicy(
                    duration=timedelta(milliseconds=50), recovery=timedelta(seconds=30)
                ),
                memory_lifecycle=LifecyclePolicy(
                    duration=timedelta(milliseconds=50), recovery=timedelta(seconds=30)
                ),
                evidence=EvidenceLimits(
                    max_system_samples=20,
                    max_contributors=3,
                    high_severity_after=timedelta(hours=1),
                ),
                pre_trigger_window=timedelta(seconds=10),
                persist_interval=timedelta(seconds=10),
                max_command_line=64,
                retention=timedelta(days=7),
                maintenance_interval=timedelta(milliseconds=10),
            ),
        )

    def test_sustained_pressure_persists_one_incident_and_maintenance_runs(self) -> None:
        repository = FakeIncidentRepository()
        store = evidence()
        engine = self._engine(repository)
        under_test = Monitor(
            system_reader=SyntheticSystemReader(busy_share=1.0),
            process_reader=SyntheticProcessReader(),
            clock=CLOCK,
            evidence=store,
            intervals=FAST,
            thresholds=THRESHOLDS,
            adaptive=ADAPTIVE,
            own_pid=OWN_PID,
            health_log_interval_seconds=0.02,
            incident_engine=engine,
        )

        health = run_until(
            under_test,
            lambda h: h.incidents_opened >= 1 and len(repository.purged_before) >= 1,
        )

        assert health.incidents_opened == 1
        assert health.incidents_live == 1
        assert health.incident_persist_failures == 0
        [incident] = repository.incidents.values()
        # Stopping the monitor ended the live incident instead of leaving it open forever.
        assert incident.status is IncidentStatus.INTERRUPTED
        assert incident.kind is IncidentKind.CPU_PRESSURE
        assert engine.live_count == 0

    def test_incidents_left_open_by_a_previous_run_are_interrupted_at_start(self) -> None:
        repository = FakeIncidentRepository()
        # Recent, so the retention purge (real clock) keeps it.
        orphan = incident("orphan", started_at=CLOCK.now() - timedelta(minutes=5), duration=None)
        repository.incidents[orphan.id] = orphan
        under_test = Monitor(
            system_reader=SyntheticSystemReader(),
            process_reader=SyntheticProcessReader(),
            clock=CLOCK,
            evidence=evidence(),
            intervals=FAST,
            thresholds=THRESHOLDS,
            adaptive=ADAPTIVE,
            own_pid=OWN_PID,
            health_log_interval_seconds=0.02,
            incident_engine=self._engine(repository),
        )

        run_until(under_test, lambda h: h.system_sample_count >= 1)

        assert repository.incidents["orphan"].status is IncidentStatus.INTERRUPTED

    def test_engine_activity_keeps_process_sampling_escalated(self) -> None:
        repository = FakeIncidentRepository()
        under_test = Monitor(
            system_reader=SyntheticSystemReader(busy_share=1.0),
            process_reader=SyntheticProcessReader(),
            clock=CLOCK,
            evidence=evidence(),
            intervals=FAST,
            thresholds=THRESHOLDS,
            adaptive=ADAPTIVE,
            own_pid=OWN_PID,
            health_log_interval_seconds=1.0,
            incident_engine=self._engine(repository),
        )

        health = run_until(under_test, lambda h: h.incidents_opened >= 1)

        assert health.mode is SamplingMode.ESCALATED


def test_the_recorded_maximum_never_falls_below_the_rounded_last_duration() -> None:
    # Regression: ``last`` was rounded up while ``max`` kept the raw value, so a health
    # snapshot could report last > max.
    stats = _timed(_LoopStats(), 0.00067720)

    assert stats.last_seconds == 0.0007
    assert stats.max_seconds >= stats.last_seconds
