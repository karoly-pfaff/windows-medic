"""Resource-hog findings: attribution over the incident window with explicit confidence."""

from datetime import timedelta

import pytest

from tests.builders import GIB, T0, contributor, identity, incident, process, process_snapshot
from tests.containers import ANCESTRY, PROTECTION
from windows_medic.domain.models.evidence import EvidenceKind
from windows_medic.domain.models.finding import (
    Confidence,
    ConfidenceReason,
    Finding,
    FindingKind,
)
from windows_medic.domain.models.incident import Incident, ProcessEvidenceSample, Severity
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.repair import RepairAction
from windows_medic.domain.models.tree import build_process_tree
from windows_medic.domain.policies.contributor_ranking import rank_contributors
from windows_medic.domain.policies.finding_assembly import FindingLimits
from windows_medic.domain.policies.protection import ProtectionLevel
from windows_medic.domain.policies.resource_hogs import HogThresholds, resource_hog_findings

TOTAL = 32 * GIB
THRESHOLDS = HogThresholds(cpu_percent=10.0, memory_percent=10.0)
LIMITS = FindingLimits(max_evidence=8, max_affected_processes=5)
WINDOW = (T0 - timedelta(minutes=30), T0)
TREE = build_process_tree(
    process_snapshot(
        process(4, name="explorer.exe"),
        process(10, name="node.exe", parent_pid=4),
        process(11, name="esbuild.exe", parent_pid=10),
        process(20, name="python.exe", parent_pid=4),
    )
)


def findings_for(
    incidents: tuple[Incident, ...],
    current: tuple[ProcessEvidenceSample, ...],
    *,
    max_findings: int = 5,
    limits: FindingLimits = LIMITS,
) -> tuple[Finding, ...]:
    ranked = rank_contributors(
        incidents, current, memory_total_bytes=TOTAL, limit=10, max_incidents_per_contributor=5
    )
    return resource_hog_findings(
        ranked,
        incidents=incidents,
        tree=TREE,
        memory_total_bytes=TOTAL,
        thresholds=THRESHOLDS,
        protection=PROTECTION,
        ancestry=ANCESTRY,
        window=WINDOW,
        limits=limits,
        max_findings=max_findings,
    )


def test_incident_contribution_confirmed_now_is_high_confidence_with_candidates() -> None:
    node = contributor(10, name="node.exe", cpu_percent=55.0)
    inc = incident("i", started_at=T0 - timedelta(minutes=5), contributors=(node,))

    (finding,) = findings_for((inc,), (contributor(10, name="node.exe", cpu_percent=30.0),))

    assert finding.kind is FindingKind.RESOURCE_HOG
    assert finding.severity is Severity.HIGH  # more than half the machine at its peak
    assert finding.confidence.level is Confidence.HIGH
    assert finding.confidence.raises == (
        ConfidenceReason.INCIDENT_CONTRIBUTION,
        ConfidenceReason.CURRENT_CONTRIBUTION,
    )
    assert finding.confidence.lowers == ()
    assert [e.kind for e in finding.evidence] == [
        EvidenceKind.INCIDENT_CONTRIBUTION,
        EvidenceKind.CURRENT_CONTRIBUTION,
    ]
    assert finding.evidence[0].incident_id == "i"
    assert finding.evidence[0].identity == identity(10)
    assert finding.evidence[0].window == inc.evidence_window
    assert finding.evidence[0].value == 55.0
    assert finding.evidence[1].value == 30.0
    assert finding.summary == (
        "node.exe (pid 10): peak 55.0 % CPU, 0.3 % of memory; 1 incident; now 30.0 % CPU, 100 MiB"
    )
    (affected,) = finding.affected_processes
    assert affected.identity == identity(10)
    assert affected.present is True
    assert affected.protection is ProtectionLevel.NONE
    assert [c.action for c in finding.candidate_repairs] == [
        RepairAction.PROCESS_TERMINATE,
        RepairAction.PROCESS_TERMINATE_TREE,
    ]
    assert finding.candidate_repairs[0].evidence == finding.evidence


def test_a_hog_that_has_exited_is_explained_but_cannot_be_repaired() -> None:
    defender = contributor(99, name="MsMpEng.exe", cpu_percent=40.0)
    inc = incident("i", started_at=T0 - timedelta(minutes=5), contributors=(defender,))

    (finding,) = findings_for((inc,), ())

    assert finding.confidence.level is Confidence.MEDIUM
    assert finding.confidence.raises == (ConfidenceReason.INCIDENT_CONTRIBUTION,)
    assert finding.confidence.lowers == ()
    assert finding.summary.endswith("; 1 incident; no longer running")
    (affected,) = finding.affected_processes
    assert affected.present is False
    assert affected.protection is ProtectionLevel.WINDOWS_COMPONENT
    assert affected.risk_markers == ()
    assert finding.candidate_repairs == ()


def test_a_current_only_hog_is_a_single_sample_with_no_recommendation() -> None:
    (finding,) = findings_for((), (contributor(20, name="python.exe", cpu_percent=45.0),))

    assert finding.confidence.level is Confidence.LOW
    assert finding.confidence.raises == (ConfidenceReason.CURRENT_CONTRIBUTION,)
    assert finding.confidence.lowers == (ConfidenceReason.SINGLE_SAMPLE_ONLY,)
    assert finding.severity is Severity.MEDIUM
    assert finding.candidate_repairs == ()
    assert finding.summary == (
        "python.exe (pid 20): peak 45.0 % CPU, 0.3 % of memory; no incident; "
        "now 45.0 % CPU, 100 MiB"
    )


def test_immaterial_contributors_are_not_findings() -> None:
    findings = findings_for((), (contributor(10, cpu_percent=9.9, working_set_bytes=3 * GIB),))

    assert findings == ()


def test_memory_share_alone_makes_a_hog() -> None:
    (finding,) = findings_for(
        (), (contributor(20, name="python.exe", cpu_percent=1.0, working_set_bytes=8 * GIB),)
    )

    assert finding.summary == (
        "python.exe (pid 20): peak 1.0 % CPU, 25.0 % of memory; no incident; "
        "now 1.0 % CPU, 8192 MiB"
    )
    assert finding.evidence[0].detail == "now 1.0 % CPU, 8192 MiB working set"


def test_severity_follows_the_incident_it_contributed_to() -> None:
    long_incident = incident(
        "long",
        started_at=T0 - timedelta(minutes=10),
        duration=timedelta(minutes=5),
        contributors=(contributor(10, name="node.exe", cpu_percent=20.0),),
    )

    (finding,) = findings_for((long_incident,), ())

    assert long_incident.severity is Severity.HIGH
    assert finding.severity is Severity.HIGH


def test_partial_metrics_now_lower_confidence() -> None:
    inc = incident(
        "i",
        started_at=T0 - timedelta(minutes=5),
        contributors=(contributor(10, name="node.exe", cpu_percent=30.0),),
    )
    now = contributor(10, name="node.exe", cpu_percent=Unavailable(UnavailableReason.NO_BASELINE))

    (finding,) = findings_for((inc,), (now,))

    assert finding.confidence.level is Confidence.MEDIUM
    assert finding.confidence.lowers == (ConfidenceReason.METRICS_PARTIAL,)
    assert finding.evidence[1].detail == "now CPU unavailable (no_baseline), 100 MiB working set"
    assert finding.candidate_repairs != ()


def test_findings_and_evidence_are_bounded() -> None:
    incidents = tuple(
        incident(
            f"i{n}",
            started_at=T0 - timedelta(minutes=20 - n),
            contributors=(contributor(10, name="node.exe", cpu_percent=30.0),),
        )
        for n in range(6)
    )
    current = tuple(
        contributor(pid, name="python.exe", cpu_percent=20.0 + pid) for pid in (20, 21, 22)
    )

    limits = FindingLimits(max_evidence=3, max_affected_processes=5)

    top_two = findings_for(incidents, current, max_findings=2, limits=limits)
    everything = findings_for(incidents, current, max_findings=10, limits=limits)

    assert [f.affected_processes[0].identity.pid for f in top_two] == [22, 21]
    assert [f.affected_processes[0].identity.pid for f in everything] == [22, 21, 20, 10]
    assert [e.incident_id for e in everything[3].evidence] == ["i5", "i4", "i3"]


@pytest.mark.parametrize(("cpu", "memory"), [(0.0, 10.0), (101.0, 10.0), (10.0, 0.0)])
def test_hog_thresholds_are_validated(cpu: float, memory: float) -> None:
    with pytest.raises(ValueError, match="within"):
        HogThresholds(cpu_percent=cpu, memory_percent=memory)


def test_memory_total_must_be_positive() -> None:
    with pytest.raises(ValueError, match="memory_total_bytes"):
        resource_hog_findings(
            (),
            incidents=(),
            tree=TREE,
            memory_total_bytes=0,
            thresholds=THRESHOLDS,
            protection=PROTECTION,
            ancestry=ANCESTRY,
            window=WINDOW,
            limits=LIMITS,
            max_findings=1,
        )


def test_an_unavailable_working_set_is_said_so() -> None:
    now = contributor(
        20,
        name="python.exe",
        cpu_percent=45.0,
        working_set_bytes=Unavailable(UnavailableReason.ACCESS_DENIED),
    )

    (finding,) = findings_for((), (now,))

    assert finding.evidence[0].detail == "now 45.0 % CPU, working set unavailable (access_denied)"
