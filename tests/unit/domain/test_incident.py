"""Incident aggregate: explainable, bounded, immutable transitions."""

from datetime import datetime, timedelta

import pytest

from tests.builders import BOOT, T0, process, process_snapshot, system
from windows_medic.domain.models.incident import (
    EvidenceLimits,
    Incident,
    IncidentKind,
    IncidentStatus,
    ProcessEvidenceSample,
    Severity,
    SystemEvidenceSample,
    begin_recovery,
    close_incident,
    interrupt_incident,
    new_incident_id,
    open_incident,
    record_system_sample,
    reopen_incident,
)
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.policies.evidence import summarise_system, top_contributors

LIMITS = EvidenceLimits(
    max_system_samples=4, max_contributors=2, high_severity_after=timedelta(seconds=120)
)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def sys_sample(seconds: float, cpu: float = 95.0) -> SystemEvidenceSample:
    return SystemEvidenceSample(
        observed_at=at(seconds),
        cpu_percent=cpu,
        memory_percent_used=50.0,
        memory_available_bytes=16 * 1024**3,
        process_count=300,
    )


def opened(pre: int = 2) -> Incident:
    return open_incident(
        incident_id="inc-1",
        kind=IncidentKind.CPU_PRESSURE,
        started_at=at(-20),
        triggered_at=at(0),
        threshold=90.0,
        pre_trigger=tuple(sys_sample(-20 + i * 10, cpu=92.0 + i) for i in range(pre)),
        contributors=(),
        evidence_window=(at(-60), at(0)),
        limits=LIMITS,
    )


class TestOpen:
    def test_open_incident_captures_trigger_facts_and_pre_trigger_evidence(self) -> None:
        incident = opened()

        assert incident.id == "inc-1"
        assert incident.kind is IncidentKind.CPU_PRESSURE
        assert incident.status is IncidentStatus.OPEN
        assert incident.severity is Severity.MEDIUM
        assert incident.started_at == at(-20)
        assert incident.triggered_at == at(0)
        assert incident.threshold == 90.0
        assert incident.peak == 93.0
        assert [s.observed_at for s in incident.system_evidence] == [at(-20), at(-10)]
        assert incident.evidence_window == (at(-60), at(0))
        assert incident.closed_at is None

    def test_pre_trigger_evidence_is_bounded_keeping_the_newest(self) -> None:
        incident = opened(pre=10)

        assert len(incident.system_evidence) == LIMITS.max_system_samples
        assert incident.system_evidence[-1].observed_at == at(-20 + 9 * 10)

    def test_peak_ignores_unavailable_values(self) -> None:
        unavailable = SystemEvidenceSample(
            observed_at=at(-5),
            cpu_percent=Unavailable(UnavailableReason.NO_BASELINE),
            memory_percent_used=1.0,
            memory_available_bytes=1,
            process_count=1,
        )
        incident = open_incident(
            incident_id="inc-2",
            kind=IncidentKind.CPU_PRESSURE,
            started_at=at(-5),
            triggered_at=at(0),
            threshold=90.0,
            pre_trigger=(unavailable,),
            contributors=(),
            evidence_window=(at(-5), at(0)),
            limits=LIMITS,
        )

        assert incident.peak == 90.0


class TestRecording:
    def test_recorded_samples_raise_the_peak_and_are_bounded(self) -> None:
        incident = opened()
        for seconds in range(1, 10):
            incident = record_system_sample(
                incident, sys_sample(seconds, cpu=90.0 + seconds), LIMITS
            )

        assert incident.peak == 99.0
        assert len(incident.system_evidence) == LIMITS.max_system_samples
        assert incident.system_evidence[0].observed_at == at(-20)
        assert incident.system_evidence[-1].observed_at == at(2)

    def test_memory_incidents_track_the_memory_figure(self) -> None:
        incident = open_incident(
            incident_id="inc-3",
            kind=IncidentKind.MEMORY_PRESSURE,
            started_at=at(-20),
            triggered_at=at(0),
            threshold=90.0,
            pre_trigger=(),
            contributors=(),
            evidence_window=(at(-60), at(0)),
            limits=LIMITS,
        )
        sample = SystemEvidenceSample(
            observed_at=at(1),
            cpu_percent=5.0,
            memory_percent_used=97.5,
            memory_available_bytes=1,
            process_count=1,
        )

        assert record_system_sample(incident, sample, LIMITS).peak == 97.5


class TestLifecycle:
    def test_recovery_and_close(self) -> None:
        recovering = begin_recovery(opened(), at(30))
        closed = close_incident(recovering, at(60), LIMITS)

        assert recovering.status is IncidentStatus.RECOVERING
        assert recovering.recovering_since == at(30)
        assert closed.status is IncidentStatus.CLOSED
        assert closed.closed_at == at(60)
        assert closed.recovering_since == at(30)

    def test_reopen_returns_to_open_and_keeps_the_identity(self) -> None:
        reopened = reopen_incident(begin_recovery(opened(), at(30)), at(40))

        assert reopened.status is IncidentStatus.OPEN
        assert reopened.recovering_since is None
        assert reopened.id == "inc-1"
        assert reopened.started_at == at(-20)

    def test_long_incidents_are_high_severity_when_closed(self) -> None:
        recovering = begin_recovery(opened(), at(150))

        assert close_incident(recovering, at(180), LIMITS).severity is Severity.HIGH
        assert close_incident(begin_recovery(opened(), at(60)), at(130), LIMITS).severity is (
            Severity.MEDIUM
        )

    def test_severity_is_reassessed_while_open(self) -> None:
        incident = record_system_sample(opened(), sys_sample(130), LIMITS)

        assert incident.severity is Severity.HIGH

    def test_illegal_transitions_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="status"):
            reopen_incident(opened(), at(1))
        with pytest.raises(ValueError, match="status"):
            close_incident(opened(), at(1), LIMITS)
        with pytest.raises(ValueError, match="status"):
            begin_recovery(begin_recovery(opened(), at(1)), at(2))

    def test_duration_is_derived(self) -> None:
        incident = opened()
        closed = close_incident(begin_recovery(incident, at(30)), at(60), LIMITS)

        assert incident.duration(at(10)) == timedelta(seconds=30)
        assert closed.duration(at(999)) == timedelta(seconds=80)


class TestInterruption:
    """Monitoring stopped while the incident was live: it ends where the evidence ends."""

    def test_an_open_incident_ends_when_it_was_last_seen(self) -> None:
        interrupted = interrupt_incident(opened(), at(40))

        assert interrupted.status is IncidentStatus.INTERRUPTED
        assert interrupted.closed_at == at(40)
        assert interrupted.recovering_since is None
        # Pressure is not extrapolated past the last observation.
        assert interrupted.pressure_duration(at(999)) == timedelta(seconds=60)
        assert interrupted.duration(at(999)) == timedelta(seconds=60)

    def test_a_recovering_incident_keeps_when_recovery_began(self) -> None:
        interrupted = interrupt_incident(begin_recovery(opened(), at(30)), at(40))

        assert interrupted.status is IncidentStatus.INTERRUPTED
        assert interrupted.recovering_since == at(30)
        assert interrupted.pressure_duration(at(999)) == timedelta(seconds=50)

    def test_it_never_ends_before_it_was_triggered(self) -> None:
        assert interrupt_incident(opened(), at(-5)).closed_at == at(0)

    def test_only_live_incidents_can_be_interrupted(self) -> None:
        closed = close_incident(begin_recovery(opened(), at(30)), at(60), LIMITS)

        with pytest.raises(ValueError, match="status"):
            interrupt_incident(closed, at(70))
        with pytest.raises(ValueError, match="status"):
            interrupt_incident(interrupt_incident(opened(), at(10)), at(20))


class TestEvidenceReduction:
    def test_summarise_system_reduces_an_observation(self) -> None:
        observation = system(observed_at=T0, available_bytes=8 * 1024**3, process_count=42)

        sample = summarise_system(observation, cpu_percent=77.5)

        assert sample == SystemEvidenceSample(
            observed_at=T0,
            cpu_percent=77.5,
            memory_percent_used=75.0,
            memory_available_bytes=8 * 1024**3,
            process_count=42,
        )

    def test_top_contributors_are_ranked_bounded_and_carry_the_window(self) -> None:
        before = process_snapshot(
            process(1, observed_at=at(-2), cpu_time_seconds=0.0, name="a.exe"),
            process(2, observed_at=at(-2), cpu_time_seconds=0.0, name="b.exe"),
            process(3, observed_at=at(-2), cpu_time_seconds=0.0, name="c.exe"),
            observed_at=at(-2),
        )
        after = process_snapshot(
            process(1, observed_at=T0, cpu_time_seconds=1.0, name="a.exe"),
            process(2, observed_at=T0, cpu_time_seconds=8.0, name="b.exe"),
            process(3, observed_at=T0, cpu_time_seconds=4.0, name="c.exe"),
            observed_at=T0,
        )

        contributors = top_contributors(before, after, cpu_count=8, limit=2, max_command_line=8)

        assert [c.identity.pid for c in contributors] == [2, 3]
        assert contributors[0].cpu_percent == pytest.approx(50.0)
        assert contributors[0].name == "b.exe"
        assert contributors[0].command_line == "b.exe"
        assert isinstance(contributors[0], ProcessEvidenceSample)

    def test_command_lines_are_truncated(self) -> None:
        long = process(1, observed_at=T0, cpu_time_seconds=1.0, name="x" * 50 + ".exe")
        before = process_snapshot(
            process(1, observed_at=at(-2), cpu_time_seconds=0.0, name="x" * 50 + ".exe"),
            observed_at=at(-2),
        )

        [contributor] = top_contributors(
            before,
            process_snapshot(long, observed_at=T0),
            cpu_count=8,
            limit=5,
            max_command_line=10,
        )

        assert contributor.command_line == "xxxxxxx..."
        assert len(contributor.command_line) == 10

    def test_contributors_without_a_baseline_are_ranked_by_memory_instead(self) -> None:
        after = process_snapshot(
            process(1, observed_at=T0, working_set_bytes=10, created=BOOT),
            process(2, observed_at=T0, working_set_bytes=30, created=BOOT),
            observed_at=T0,
        )

        contributors = top_contributors(None, after, cpu_count=8, limit=5, max_command_line=100)

        assert [c.identity.pid for c in contributors] == [2, 1]
        assert contributors[0].cpu_percent == Unavailable(UnavailableReason.NO_BASELINE)


def test_incident_is_immutable() -> None:
    incident = opened()

    with pytest.raises(AttributeError):
        incident.status = IncidentStatus.CLOSED  # type: ignore[misc]


def test_new_incident_ids_are_unique_uuid_hex() -> None:
    first, second = new_incident_id(), new_incident_id()

    assert first != second
    assert len(first) == 32


@pytest.mark.parametrize(
    ("samples", "contributors", "after", "message"),
    [
        (0, 1, timedelta(seconds=1), "max_system_samples"),
        (1, -1, timedelta(seconds=1), "max_contributors"),
        (1, 1, timedelta(0), "high_severity_after"),
    ],
)
def test_evidence_limits_are_validated(
    samples: int, contributors: int, after: timedelta, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        EvidenceLimits(
            max_system_samples=samples, max_contributors=contributors, high_severity_after=after
        )
