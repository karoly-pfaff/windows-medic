"""Pressure findings: incidents in the window plus the current sample, with explicit confidence."""

from datetime import timedelta

from tests.builders import GIB, T0, incident, system_sample
from windows_medic.domain.models.evidence import EvidenceKind
from windows_medic.domain.models.finding import Confidence, ConfidenceReason, FindingKind
from windows_medic.domain.models.incident import IncidentKind, Severity, interrupt_incident
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.policies.finding_assembly import FindingLimits
from windows_medic.domain.policies.pressure import PressureSignal, PressureThresholds
from windows_medic.domain.policies.pressure_findings import pressure_findings

THRESHOLDS = PressureThresholds(
    cpu_percent=90.0, memory_percent=90.0, memory_available_floor_bytes=int(1.5 * GIB)
)
LIMITS = FindingLimits(max_evidence=8, max_affected_processes=5)
WINDOW = (T0 - timedelta(minutes=30), T0)
CALM = PressureSignal(cpu=False, memory=False)
CPU_HOT = PressureSignal(cpu=True, memory=False)


def test_no_incidents_and_no_current_pressure_means_no_findings() -> None:
    findings = pressure_findings(
        (),
        current=system_sample(cpu_percent=20.0),
        signal=CALM,
        thresholds=THRESHOLDS,
        window=WINDOW,
        limits=LIMITS,
    )

    assert findings == ()


def test_open_incident_confirmed_by_the_current_sample_is_high_confidence() -> None:
    open_incident = incident("inc-open", started_at=T0 - timedelta(minutes=3), duration=None)

    (finding,) = pressure_findings(
        (open_incident,),
        current=system_sample(cpu_percent=96.0),
        signal=CPU_HOT,
        thresholds=THRESHOLDS,
        window=WINDOW,
        limits=LIMITS,
    )

    assert finding.kind is FindingKind.CPU_PRESSURE
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence.level is Confidence.HIGH
    assert finding.confidence.raises == (
        ConfidenceReason.SUSTAINED_INCIDENT,
        ConfidenceReason.PRESSURE_ONGOING,
        ConfidenceReason.CURRENT_SAMPLE_CONFIRMS,
    )
    assert finding.confidence.lowers == ()
    assert finding.window == WINDOW
    assert [e.kind for e in finding.evidence] == [
        EvidenceKind.CURRENT_PRESSURE,
        EvidenceKind.INCIDENT,
    ]
    assert finding.evidence[0].value == 96.0
    assert finding.evidence[1].incident_id == "inc-open"
    assert finding.evidence[1].value == 95.0
    assert finding.evidence[1].window == (T0 - timedelta(minutes=3), T0)
    assert finding.summary == (
        "CPU pressure: 1 incident, peak 95.0 % (threshold 90.0 %), ongoing; now 96.0 %"
    )
    assert finding.affected_processes == ()
    assert finding.candidate_repairs == ()


def test_resolved_incidents_without_current_pressure_are_medium_confidence() -> None:
    incidents = (
        incident("a", started_at=T0 - timedelta(minutes=20), duration=timedelta(minutes=5)),
        incident("b", started_at=T0 - timedelta(minutes=8), peak=99.0),
    )

    (finding,) = pressure_findings(
        incidents,
        current=system_sample(cpu_percent=12.0),
        signal=CALM,
        thresholds=THRESHOLDS,
        window=WINDOW,
        limits=LIMITS,
    )

    assert finding.confidence.level is Confidence.MEDIUM
    assert finding.confidence.raises == (
        ConfidenceReason.SUSTAINED_INCIDENT,
        ConfidenceReason.REPEATED_INCIDENTS,
    )
    assert finding.severity is Severity.HIGH  # the five-minute incident was high severity
    assert [e.incident_id for e in finding.evidence] == ["b", "a"]
    assert finding.evidence[1].window == (
        T0 - timedelta(minutes=20),
        T0 - timedelta(minutes=20) + timedelta(minutes=5, seconds=30),
    )
    assert finding.summary == (
        "CPU pressure: 2 incidents, peak 99.0 % (threshold 90.0 %), resolved; now 12.0 %"
    )


def test_an_interrupted_incident_is_past_evidence_not_ongoing_pressure() -> None:
    # The agent stopped (reboot, crash) mid-incident; nothing says the pressure continues.
    left_open = incident("ghost", started_at=T0 - timedelta(minutes=12), duration=None)
    interrupted = interrupt_incident(left_open, T0 - timedelta(minutes=10))

    (finding,) = pressure_findings(
        (interrupted,),
        current=system_sample(cpu_percent=12.0),
        signal=CALM,
        thresholds=THRESHOLDS,
        window=WINDOW,
        limits=LIMITS,
    )

    assert finding.confidence.level is Confidence.MEDIUM
    assert ConfidenceReason.PRESSURE_ONGOING not in finding.confidence.raises
    assert finding.evidence[0].window == (T0 - timedelta(minutes=12), T0 - timedelta(minutes=10))
    assert "interrupted" in finding.evidence[0].detail
    assert "ongoing" not in finding.summary


def test_current_pressure_without_incidents_is_a_single_sample_low_confidence() -> None:
    (finding,) = pressure_findings(
        (),
        current=system_sample(cpu_percent=97.0),
        signal=CPU_HOT,
        thresholds=THRESHOLDS,
        window=WINDOW,
        limits=LIMITS,
    )

    assert finding.confidence.level is Confidence.LOW
    assert finding.confidence.raises == ()
    assert finding.confidence.lowers == (ConfidenceReason.SINGLE_SAMPLE_ONLY,)
    assert finding.severity is Severity.MEDIUM
    assert [e.kind for e in finding.evidence] == [EvidenceKind.CURRENT_PRESSURE]
    assert finding.summary == (
        "CPU pressure: 97.0 % now (threshold 90.0 %); no sustained incident recorded"
    )


def test_memory_findings_use_the_memory_figures() -> None:
    memory_incident = incident(
        "m",
        kind=IncidentKind.MEMORY_PRESSURE,
        started_at=T0 - timedelta(minutes=2),
        duration=None,
        peak=93.0,
    )

    (finding,) = pressure_findings(
        (memory_incident,),
        current=system_sample(cpu_percent=10.0, memory_percent_used=94.0),
        signal=PressureSignal(cpu=False, memory=True),
        thresholds=THRESHOLDS,
        window=WINDOW,
        limits=LIMITS,
    )

    assert finding.kind is FindingKind.MEMORY_PRESSURE
    assert finding.evidence[0].value == 94.0
    assert finding.evidence[1].value == 93.0
    assert finding.summary.startswith("Memory pressure: 1 incident, peak 93.0 %")


def test_both_kinds_are_reported_separately_cpu_first() -> None:
    incidents = (
        incident("m", kind=IncidentKind.MEMORY_PRESSURE, started_at=T0 - timedelta(minutes=2)),
        incident("c", started_at=T0 - timedelta(minutes=4)),
    )

    findings = pressure_findings(
        incidents,
        current=system_sample(cpu_percent=10.0),
        signal=CALM,
        thresholds=THRESHOLDS,
        window=WINDOW,
        limits=LIMITS,
    )

    assert [f.kind for f in findings] == [FindingKind.CPU_PRESSURE, FindingKind.MEMORY_PRESSURE]


def test_unavailable_current_cpu_lowers_confidence_and_is_said_so() -> None:
    (finding,) = pressure_findings(
        (incident("c", started_at=T0 - timedelta(minutes=4)),),
        current=system_sample(cpu_percent=Unavailable(UnavailableReason.INCONSISTENT)),
        signal=CALM,
        thresholds=THRESHOLDS,
        window=WINDOW,
        limits=LIMITS,
    )

    assert finding.confidence.level is Confidence.MEDIUM
    assert finding.confidence.lowers == (ConfidenceReason.METRICS_PARTIAL,)
    assert finding.summary.endswith("; now unavailable")


def test_evidence_is_bounded_newest_incidents_first() -> None:
    incidents = tuple(
        incident(f"i{n}", started_at=T0 - timedelta(minutes=25 - n)) for n in range(6)
    )

    (finding,) = pressure_findings(
        incidents,
        current=system_sample(cpu_percent=95.0),
        signal=CPU_HOT,
        thresholds=THRESHOLDS,
        window=WINDOW,
        limits=FindingLimits(max_evidence=3, max_affected_processes=5),
    )

    assert len(finding.evidence) == 3
    assert [e.incident_id for e in finding.evidence] == [None, "i5", "i4"]
