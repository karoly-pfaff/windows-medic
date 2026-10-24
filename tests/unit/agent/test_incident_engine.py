"""IncidentEngine: sustained pressure -> one incident with pre-trigger evidence, persisted
with bounded, throttled writes that never take the monitor down."""

import logging
from datetime import datetime, timedelta

import pytest

from tests.builders import GIB, T0, process, process_snapshot, system
from tests.fakes import FakeIncidentRepository
from windows_medic.domain.errors import IncidentStoreError
from windows_medic.domain.models.incident import (
    EvidenceLimits,
    IncidentKind,
    IncidentStatus,
)
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.policies.pressure import PressureThresholds
from windows_medic.domain.policies.pressure_lifecycle import LifecyclePolicy
from windows_medic_agent.evidence import EvidenceRetention, RollingEvidence
from windows_medic_agent.incident_engine import IncidentEngine, IncidentPolicy

POLICY = IncidentPolicy(
    thresholds=PressureThresholds(
        cpu_percent=90.0, memory_percent=90.0, memory_available_floor_bytes=int(1.5 * GIB)
    ),
    cpu_lifecycle=LifecyclePolicy(duration=timedelta(seconds=20), recovery=timedelta(seconds=30)),
    memory_lifecycle=LifecyclePolicy(
        duration=timedelta(seconds=20), recovery=timedelta(seconds=30)
    ),
    evidence=EvidenceLimits(
        max_system_samples=50, max_contributors=3, high_severity_after=timedelta(seconds=120)
    ),
    pre_trigger_window=timedelta(seconds=10),
    persist_interval=timedelta(seconds=10),
    max_command_line=64,
    retention=timedelta(days=7),
    maintenance_interval=timedelta(hours=1),
)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


class Harness:
    """Feeds system samples every 2 s; CPU busy share is chosen per sample."""

    def __init__(self, *, fail_saves: set[int] | None = None) -> None:
        self.repository = FakeIncidentRepository()
        self.repository.fail_saves = fail_saves or set()
        self.evidence = RollingEvidence(
            EvidenceRetention(
                window=timedelta(minutes=30), max_system_samples=1000, max_process_snapshots=100
            )
        )
        self.engine = IncidentEngine(
            repository=self.repository, evidence=self.evidence, policy=POLICY, ids=self._next_id
        )
        self._ids = 0
        self._busy = 0.0
        self._total = 0.0

    def _next_id(self) -> str:
        self._ids += 1
        return f"inc-{self._ids}"

    def tick(self, seconds: float, *, cpu: float, available_bytes: int = 16 * GIB) -> None:
        """Record one system sample at *seconds* with the given CPU % since the last one."""
        self._busy += 2.0 * cpu / 100.0
        self._total += 2.0
        observation = system(
            observed_at=at(seconds),
            busy_seconds=self._busy,
            total_seconds=self._total,
            available_bytes=available_bytes,
        )
        self.evidence.record_system(observation)
        self.engine.observe(observation, cpu_percent=cpu)

    def run(self, start: float, end: float, *, cpu: float, step: float = 2.0) -> None:
        seconds = start
        while seconds <= end:
            self.tick(seconds, cpu=cpu)
            seconds += step

    def processes(self, seconds: float, *cpu_times: tuple[int, float]) -> None:
        snapshot = process_snapshot(
            *(
                process(pid, observed_at=at(seconds), cpu_time_seconds=cpu_time, name=f"p{pid}.exe")
                for pid, cpu_time in cpu_times
            ),
            observed_at=at(seconds),
        )
        self.evidence.record_processes(snapshot)


class TestOpening:
    def test_sustained_pressure_opens_exactly_one_incident(self) -> None:
        harness = Harness()

        harness.run(0, 120, cpu=95.0)

        assert harness.engine.opened_count == 1
        [incident] = harness.repository.incidents.values()
        assert incident.kind is IncidentKind.CPU_PRESSURE
        assert incident.status is IncidentStatus.OPEN
        assert incident.started_at == at(0)
        assert incident.triggered_at == at(20)
        assert incident.threshold == 90.0
        assert incident.peak == pytest.approx(95.0)

    def test_brief_spike_below_the_duration_does_not_open(self) -> None:
        harness = Harness()

        harness.run(0, 18, cpu=95.0)
        harness.run(20, 60, cpu=10.0)

        assert harness.engine.opened_count == 0
        assert harness.repository.saves == 0

    def test_pre_trigger_evidence_comes_from_the_rolling_buffer(self) -> None:
        harness = Harness()
        harness.run(-30, -2, cpu=10.0)

        harness.run(0, 20, cpu=95.0)

        [incident] = harness.repository.incidents.values()
        observed = [s.observed_at for s in incident.system_evidence]
        assert observed[0] == at(10)  # 10 s pre-trigger window before the trigger at 20
        assert observed[-1] == at(20)
        assert incident.evidence_window == (at(10), at(20))
        assert all(s.cpu_percent == pytest.approx(95.0) for s in incident.system_evidence[1:])

    def test_contributors_come_from_the_last_two_process_snapshots(self) -> None:
        harness = Harness()
        harness.processes(14, (1, 0.0), (2, 0.0), (3, 0.0), (4, 0.0))
        harness.processes(18, (1, 1.0), (2, 8.0), (3, 4.0), (4, 2.0))

        harness.run(0, 20, cpu=95.0)

        [incident] = harness.repository.incidents.values()
        assert [c.identity.pid for c in incident.contributors] == [2, 3, 4]
        assert incident.contributors[0].name == "p2.exe"
        assert incident.contributors[0].cpu_percent == pytest.approx(25.0)

    def test_no_process_snapshots_yet_means_no_contributors(self) -> None:
        harness = Harness()

        harness.run(0, 20, cpu=95.0)

        [incident] = harness.repository.incidents.values()
        assert incident.contributors == ()

    def test_memory_pressure_is_tracked_independently(self) -> None:
        harness = Harness()

        for seconds in range(0, 22, 2):
            harness.tick(seconds, cpu=95.0, available_bytes=1 * GIB)

        kinds = {i.kind for i in harness.repository.incidents.values()}
        assert kinds == {IncidentKind.CPU_PRESSURE, IncidentKind.MEMORY_PRESSURE}
        assert harness.engine.opened_count == 2


class TestLifecycle:
    def test_recovery_closes_the_incident_after_the_cool_down(self) -> None:
        harness = Harness()
        harness.run(0, 40, cpu=95.0)

        harness.run(42, 70, cpu=10.0)
        assert next(iter(harness.repository.incidents.values())).status is IncidentStatus.RECOVERING
        harness.run(72, 80, cpu=10.0)

        [incident] = harness.repository.incidents.values()
        assert incident.status is IncidentStatus.CLOSED
        assert incident.recovering_since == at(42)
        assert incident.closed_at == at(72)
        assert not harness.engine.active

    def test_pressure_returning_during_recovery_extends_the_same_incident(self) -> None:
        harness = Harness()
        harness.run(0, 40, cpu=95.0)
        harness.run(42, 50, cpu=10.0)

        harness.run(52, 100, cpu=95.0)

        assert harness.engine.opened_count == 1
        [incident] = harness.repository.incidents.values()
        assert incident.id == "inc-1"
        assert incident.status is IncidentStatus.OPEN

    def test_engine_is_active_while_suspect_or_open(self) -> None:
        harness = Harness()
        # mypy narrows a property across statements; read it through a call instead.
        states = [harness.engine.active]

        harness.tick(0, cpu=95.0)
        states.append(harness.engine.active)
        harness.run(2, 40, cpu=95.0)
        states.append(harness.engine.active)

        assert states == [False, True, True]

    def test_unavailable_cpu_never_counts_as_pressure(self) -> None:
        harness = Harness()
        observation = system(observed_at=T0)

        harness.engine.observe(observation, cpu_percent=Unavailable(UnavailableReason.NO_BASELINE))

        assert not harness.engine.active


class TestPersistence:
    def test_writes_are_throttled_while_open_but_transitions_are_immediate(self) -> None:
        harness = Harness()

        harness.run(0, 20, cpu=95.0)
        assert harness.repository.saves == 1  # opened
        harness.run(22, 28, cpu=95.0)
        assert harness.repository.saves == 1  # within persist_interval: no extra writes
        harness.run(30, 32, cpu=95.0)
        assert harness.repository.saves == 2  # 10 s later: one throttled update
        harness.run(34, 34, cpu=10.0)
        assert harness.repository.saves == 3  # recovery transition is written immediately

    def test_store_failures_are_counted_and_retried_without_stopping_the_engine(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        harness = Harness(fail_saves={1, 2})

        with caplog.at_level(logging.WARNING, logger="windows_medic_agent.incident_engine"):
            harness.run(0, 60, cpu=95.0)

        assert harness.engine.persist_failures == 2
        assert harness.engine.opened_count == 1
        assert "inc-1" in harness.repository.incidents
        assert "incident.persist_failed" in [r.getMessage() for r in caplog.records]

    def test_a_failed_close_is_retried_until_it_lands(self) -> None:
        harness = Harness()
        harness.run(0, 40, cpu=95.0)
        harness.run(42, 70, cpu=10.0)
        harness.repository.fail_saves = {harness.repository.saves + 1}

        harness.run(72, 90, cpu=10.0)

        [incident] = harness.repository.incidents.values()
        assert incident.status is IncidentStatus.CLOSED
        assert harness.engine.persist_failures == 1


class TestInterruption:
    def test_incidents_a_previous_run_left_live_are_interrupted_and_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        previous = Harness()
        previous.run(0, 40, cpu=95.0)  # the previous agent died here, incident still open
        harness = Harness()
        harness.repository.incidents = previous.repository.incidents

        with caplog.at_level(logging.INFO, logger="windows_medic_agent.incident_engine"):
            harness.engine.interrupt_orphans()

        [incident] = harness.repository.incidents.values()
        assert incident.status is IncidentStatus.INTERRUPTED
        assert "incident.interrupted" in [r.getMessage() for r in caplog.records]

    def test_a_store_failure_while_interrupting_is_logged_not_raised(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        harness = Harness()
        harness.repository.fail_reads = "database is locked"

        with caplog.at_level(logging.WARNING, logger="windows_medic_agent.incident_engine"):
            harness.engine.interrupt_orphans()

        assert "incident.interrupt_failed" in [r.getMessage() for r in caplog.records]

    def test_stopping_interrupts_the_live_incidents_at_the_stop_time(self) -> None:
        harness = Harness()
        harness.run(0, 40, cpu=95.0)

        harness.engine.interrupt_live(at(41))

        [incident] = harness.repository.incidents.values()
        assert incident.status is IncidentStatus.INTERRUPTED
        assert incident.closed_at == at(41)
        assert harness.engine.live_count == 0

    def test_stopping_without_live_incidents_writes_nothing(self) -> None:
        harness = Harness()
        harness.run(0, 10, cpu=10.0)

        harness.engine.interrupt_live(at(11))

        assert harness.repository.saves == 0

    def test_a_failed_write_on_stop_is_logged_not_raised(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        harness = Harness()
        harness.run(0, 40, cpu=95.0)
        harness.repository.fail_saves = {harness.repository.saves + 1}

        with caplog.at_level(logging.WARNING, logger="windows_medic_agent.incident_engine"):
            harness.engine.interrupt_live(at(41))

        assert "incident.persist_failed" in [r.getMessage() for r in caplog.records]
        assert harness.engine.persist_failures == 1


class TestMaintenance:
    def test_retention_purge_runs_once_per_maintenance_interval(self) -> None:
        harness = Harness()

        harness.engine.maintain(at(0))
        harness.engine.maintain(at(1800))
        harness.engine.maintain(at(3600))

        assert harness.repository.purged_before == [
            at(0) - POLICY.retention,
            at(3600) - POLICY.retention,
        ]

    def test_purge_failure_is_logged_not_raised(self, caplog: pytest.LogCaptureFixture) -> None:
        harness = Harness()

        def failing(cutoff: datetime) -> int:
            raise IncidentStoreError("disk on fire")

        harness.repository.purge_older_than = failing  # type: ignore[method-assign]
        with caplog.at_level(logging.WARNING, logger="windows_medic_agent.incident_engine"):
            harness.engine.maintain(at(0))

        assert "incident.maintenance_failed" in [r.getMessage() for r in caplog.records]
