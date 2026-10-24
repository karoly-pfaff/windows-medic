"""DiagnoseSlowdown: bounded lookback, evidence from the incident window, ranked findings."""

from dataclasses import replace
from datetime import timedelta

import pytest

from tests.builders import (
    GIB,
    T0,
    contributor,
    identity,
    incident,
    process,
    process_snapshot,
    system,
)
from tests.containers import ANCESTRY, PROTECTION
from tests.fakes import (
    FakeClock,
    FakeHungWindowReader,
    FakeIncidentRepository,
    FakeProcessReader,
    FakeSystemReader,
)
from windows_medic.application.use_cases.diagnose_slowdown import (
    DiagnoseSlowdown,
    DiagnosisLimits,
    DiagnosisPolicy,
)
from windows_medic.application.use_cases.get_system_health import HealthLimits
from windows_medic.domain.models.finding import Confidence, FindingKind
from windows_medic.domain.models.gui import HungWindow
from windows_medic.domain.models.incident import Incident, IncidentKind, Severity
from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.samples import ProcessSnapshot, SystemObservation
from windows_medic.domain.policies.finding_assembly import FindingLimits
from windows_medic.domain.policies.pressure import PressureThresholds
from windows_medic.domain.policies.process_classification import DevelopmentClassifier
from windows_medic.domain.policies.resource_hogs import HogThresholds

T1 = T0 + timedelta(seconds=1)
OLD = T0 - timedelta(hours=2)
GONE_PARENT = 777

POLICY = DiagnosisPolicy(
    pressure=PressureThresholds(
        cpu_percent=90.0, memory_percent=90.0, memory_available_floor_bytes=int(1.5 * GIB)
    ),
    hogs=HogThresholds(cpu_percent=10.0, memory_percent=10.0),
    stale_after=timedelta(minutes=30),
    classifier=DevelopmentClassifier(
        process_names=("node.exe", "esbuild.exe"), command_markers=("vite",)
    ),
    protection=PROTECTION,
    ancestry=ANCESTRY,
    max_command_line=200,
)
LIMITS = DiagnosisLimits(
    default_lookback=timedelta(minutes=30),
    max_lookback=timedelta(hours=4),
    max_incidents=5,
    max_findings=10,
    max_hogs=3,
    max_stale_trees=3,
    max_hung_processes=3,
    max_incidents_per_contributor=3,
    finding=FindingLimits(max_evidence=6, max_affected_processes=4),
    measurement=HealthLimits(measurement_window_seconds=1.0, top_contributors=5),
)


def calm_system() -> tuple[SystemObservation, SystemObservation]:
    return (
        system(observed_at=T0),
        system(observed_at=T1, busy_seconds=1000.8, total_seconds=10_008.0),  # 10 % busy
    )


def hot_system() -> tuple[SystemObservation, SystemObservation]:
    return (
        system(observed_at=T0),
        system(observed_at=T1, busy_seconds=1007.6, total_seconds=10_008.0),  # 95 % busy
    )


def snapshots(
    *processes: ProcessObservation, busy: dict[int, float] | None = None
) -> tuple[ProcessSnapshot, ProcessSnapshot]:
    """The same processes one second apart; *busy* maps pid -> CPU seconds consumed (8 cores)."""
    consumed = busy or {}
    before = process_snapshot(*processes, observed_at=T0)
    after = process_snapshot(
        *(
            replace(
                p,
                observed_at=T1,
                cpu_time_seconds=float(p.cpu_time_seconds) + consumed.get(p.identity.pid, 0.0)
                if available(p.cpu_time_seconds)
                else p.cpu_time_seconds,
            )
            for p in processes
        ),
        observed_at=T1,
    )
    return before, after


def build(
    *,
    incidents: tuple[Incident, ...] = (),
    systems: tuple[SystemObservation, SystemObservation] | None = None,
    processes: tuple[ProcessSnapshot, ProcessSnapshot] | None = None,
    hung: tuple[HungWindow, ...] = (),
    lookup: ProcessSnapshot | None = None,
    limits: DiagnosisLimits = LIMITS,
) -> tuple[DiagnoseSlowdown, FakeIncidentRepository, FakeClock]:
    repository = FakeIncidentRepository()
    for inc in incidents:
        repository.save(inc)
    before, after = (
        processes if processes is not None else snapshots(process(4, name="explorer.exe"))
    )
    clock = FakeClock(T0)
    use_case = DiagnoseSlowdown(
        system_reader=FakeSystemReader(*(systems or calm_system())),
        process_reader=FakeProcessReader(before, after, lookup=lookup),
        incident_repository=repository,
        hung_window_reader=FakeHungWindowReader(*hung),
        clock=clock,
        policy=POLICY,
        limits=limits,
    )
    return use_case, repository, clock


class TestLookback:
    def test_default_lookback_is_applied_and_the_window_is_reported(self) -> None:
        use_case, repository, _ = build()

        diagnosis = use_case.execute()

        assert diagnosis.lookback == (T0 - timedelta(minutes=30), T1)
        assert diagnosis.observed_at == T1
        assert repository.active_since_calls == [(T0 - timedelta(minutes=30), 6)]

    @pytest.mark.parametrize("lookback", [timedelta(0), timedelta(minutes=-1), timedelta(hours=5)])
    def test_lookback_outside_the_bounds_is_rejected(self, lookback: timedelta) -> None:
        use_case, _, _ = build()

        with pytest.raises(ValueError, match="lookback"):
            use_case.execute(lookback)

    def test_incidents_in_the_window_are_summarised_newest_first_and_bounded(self) -> None:
        incidents = tuple(
            incident(f"i{n}", started_at=T0 - timedelta(minutes=25 - n)) for n in range(7)
        )
        use_case, _, _ = build(incidents=incidents)

        diagnosis = use_case.execute(timedelta(hours=1))

        assert [i.id for i in diagnosis.incidents] == ["i6", "i5", "i4", "i3", "i2"]
        assert diagnosis.incidents_truncated is True
        assert diagnosis.evidence.incidents_in_window == 5


class TestCalmMachine:
    def test_no_evidence_means_no_findings_even_with_development_processes(self) -> None:
        # node.exe with a live parent, idle: a common name alone is not a finding.
        use_case, _, clock = build(
            processes=snapshots(
                process(4, name="explorer.exe"),
                process(10, name="node.exe", created=OLD, parent_pid=4),
            )
        )

        diagnosis = use_case.execute()

        assert diagnosis.findings == ()
        assert diagnosis.findings_truncated is False
        assert diagnosis.pressure_now.cpu is False
        assert diagnosis.current.cpu_percent == pytest.approx(10.0)
        assert clock.sleeps == [1.0]
        assert diagnosis.evidence.processes_observed == 2
        assert diagnosis.evidence.hung_windows == 0


class TestCompetingContributors:
    def test_incident_window_attribution_outranks_the_current_sample(self) -> None:
        # A drove an incident and has exited; B is busy right now only.
        inc = incident(
            "i",
            started_at=T0 - timedelta(minutes=5),
            contributors=(contributor(100, name="build.exe", cpu_percent=60.0),),
        )
        use_case, _, _ = build(
            incidents=(inc,),
            systems=calm_system(),
            processes=snapshots(
                process(4, name="explorer.exe"), process(20, name="python.exe"), busy={20: 2.4}
            ),
        )

        diagnosis = use_case.execute()

        hogs = [f for f in diagnosis.findings if f.kind is FindingKind.RESOURCE_HOG]
        assert [f.affected_processes[0].identity.pid for f in hogs] == [100, 20]
        assert hogs[0].confidence.level is Confidence.MEDIUM
        assert hogs[0].affected_processes[0].present is False
        assert hogs[0].candidate_repairs == ()
        assert hogs[1].confidence.level is Confidence.LOW
        assert hogs[1].evidence[0].value == pytest.approx(30.0)
        assert diagnosis.findings[0].kind is FindingKind.CPU_PRESSURE
        assert diagnosis.findings[0].confidence.level is Confidence.MEDIUM

    def test_an_open_incident_confirmed_now_yields_high_confidence_and_candidates(
        self,
    ) -> None:
        inc = incident(
            "i",
            started_at=T0 - timedelta(minutes=2),
            duration=None,
            contributors=(contributor(20, name="python.exe", cpu_percent=70.0),),
        )
        use_case, _, _ = build(
            incidents=(inc,),
            systems=hot_system(),
            processes=snapshots(
                process(4, name="explorer.exe"), process(20, name="python.exe"), busy={20: 6.0}
            ),
        )

        diagnosis = use_case.execute()

        assert diagnosis.pressure_now.cpu is True
        # The hog took 70 % of the machine (high severity); the incident itself is still
        # medium severity, so attribution ranks first.
        assert [f.kind for f in diagnosis.findings] == [
            FindingKind.RESOURCE_HOG,
            FindingKind.CPU_PRESSURE,
        ]
        hog, pressure = diagnosis.findings
        assert hog.severity is Severity.HIGH
        assert pressure.severity is Severity.MEDIUM
        assert pressure.confidence.level is Confidence.HIGH
        assert hog.confidence.level is Confidence.HIGH
        assert hog.affected_processes[0].present is True
        assert [c.target for c in hog.candidate_repairs] == [identity(20)]
        assert hog.candidate_repairs[0].eligible is True


class TestAmbiguousEvidence:
    def test_orphan_development_tree_needs_parent_evidence_not_a_name(self) -> None:
        use_case, _, _ = build(
            processes=snapshots(
                process(4, name="explorer.exe"),
                process(10, name="node.exe", created=OLD, parent_pid=GONE_PARENT),
                process(11, name="esbuild.exe", created=OLD, parent_pid=10),
                process(12, name="node.exe", created=OLD, parent_pid=4),
            )
        )

        diagnosis = use_case.execute()

        (finding,) = diagnosis.findings
        assert finding.kind is FindingKind.SUSPECTED_STALE_DEV_TREE
        assert [a.identity.pid for a in finding.affected_processes] == [10, 11]
        assert finding.confidence.level is Confidence.HIGH
        assert finding.candidate_repairs[1].scope.value == "tree"

    def test_a_young_orphan_gets_no_recommendation(self) -> None:
        use_case, _, _ = build(
            processes=snapshots(
                process(
                    10, name="node.exe", created=T0 - timedelta(minutes=3), parent_pid=GONE_PARENT
                )
            )
        )

        (finding,) = use_case.execute().findings

        assert finding.confidence.level is Confidence.LOW
        assert finding.candidate_repairs == ()


class TestHungWindows:
    def test_hung_windows_are_attributed_by_verified_identity(self) -> None:
        before, after = snapshots(process(4, name="explorer.exe"), process(30, name="app.exe"))
        use_case, _, _ = build(
            processes=(before, after),
            hung=(HungWindow(30, "Editor"), HungWindow(31, "Vanished")),
            lookup=process_snapshot(process(4, name="explorer.exe"), process(30, name="app.exe")),
        )

        diagnosis = use_case.execute()

        hung = [f for f in diagnosis.findings if f.kind is FindingKind.HUNG_GUI]
        assert [f.confidence.level for f in hung] == [Confidence.HIGH, Confidence.LOW]
        assert hung[0].affected_processes[0].identity == identity(30)
        assert hung[1].summary == "1 hung window whose owner could not be verified"
        assert diagnosis.evidence.hung_windows == 2
        assert diagnosis.evidence.hung_windows_unverified == 1

    def test_an_owner_that_changed_between_reads_is_unverified(self) -> None:
        before, after = snapshots(process(30, name="app.exe"))
        use_case, _, _ = build(
            processes=(before, after),
            hung=(HungWindow(30, "Editor"),),
            lookup=process_snapshot(process(30, name="other.exe", created=T1)),
        )

        (finding,) = use_case.execute().findings

        assert finding.confidence.level is Confidence.LOW
        assert finding.affected_processes == ()


class TestBounds:
    def test_findings_are_ranked_and_bounded(self) -> None:
        limits = DiagnosisLimits(
            default_lookback=timedelta(minutes=30),
            max_lookback=timedelta(hours=4),
            max_incidents=5,
            max_findings=2,
            max_hogs=3,
            max_stale_trees=3,
            max_hung_processes=3,
            max_incidents_per_contributor=3,
            finding=FindingLimits(max_evidence=6, max_affected_processes=4),
            measurement=HealthLimits(measurement_window_seconds=1.0, top_contributors=5),
        )
        use_case, _, _ = build(
            systems=hot_system(),
            processes=snapshots(
                process(4, name="explorer.exe"),
                process(20, name="python.exe"),
                process(21, name="java.exe"),
                process(10, name="node.exe", created=OLD, parent_pid=GONE_PARENT),
                busy={20: 3.0, 21: 2.0},
            ),
            limits=limits,
        )

        diagnosis = use_case.execute()

        assert len(diagnosis.findings) == 2
        assert diagnosis.findings_truncated is True
        assert diagnosis.findings[0].kind is FindingKind.CPU_PRESSURE

    def test_limits_are_validated(self) -> None:
        with pytest.raises(ValueError, match="max_lookback"):
            DiagnosisLimits(
                default_lookback=timedelta(minutes=30),
                max_lookback=timedelta(minutes=10),
                max_incidents=5,
                max_findings=2,
                max_hogs=3,
                max_stale_trees=3,
                max_hung_processes=3,
                max_incidents_per_contributor=3,
                finding=FindingLimits(max_evidence=6, max_affected_processes=4),
                measurement=HealthLimits(measurement_window_seconds=1.0, top_contributors=5),
            )


def test_memory_incidents_are_diagnosed_too() -> None:
    inc = incident(
        "m", kind=IncidentKind.MEMORY_PRESSURE, started_at=T0 - timedelta(minutes=3), peak=94.0
    )
    use_case, _, _ = build(incidents=(inc,))

    diagnosis = use_case.execute()

    assert [f.kind for f in diagnosis.findings] == [FindingKind.MEMORY_PRESSURE]
    assert diagnosis.evidence.incident_system_samples == 1


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"default_lookback": timedelta(0)}, "default_lookback"),
        ({"max_findings": 0}, "max_findings"),
        ({"max_incidents_per_contributor": 0}, "max_incidents_per_contributor"),
    ],
)
def test_every_limit_is_validated(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        replace(LIMITS, **overrides)  # type: ignore[arg-type]


def test_windows_of_one_owner_resolve_its_identity_once() -> None:
    before, after = snapshots(process(4, name="explorer.exe"), process(30, name="app.exe"))
    use_case, _, _ = build(
        processes=(before, after),
        hung=(HungWindow(30, "One"), HungWindow(30, "Two")),
    )

    diagnosis = use_case.execute()

    (finding,) = [f for f in diagnosis.findings if f.kind is FindingKind.HUNG_GUI]
    assert len(finding.evidence) == 2
    assert diagnosis.evidence.hung_windows_unverified == 0
