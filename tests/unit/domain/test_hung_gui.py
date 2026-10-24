"""Hung GUI findings: Windows' own not-responding verdict, attributed by exact identity."""

from datetime import timedelta

from tests.builders import T0, identity, process, process_snapshot
from tests.containers import ANCESTRY, PROTECTION
from windows_medic.domain.models.evidence import EvidenceKind
from windows_medic.domain.models.finding import Confidence, ConfidenceReason, FindingKind
from windows_medic.domain.models.gui import HungWindow
from windows_medic.domain.models.incident import Severity
from windows_medic.domain.models.repair import RepairAction, RepairBlocker, RiskLevel
from windows_medic.domain.models.tree import build_process_tree
from windows_medic.domain.policies.finding_assembly import FindingLimits
from windows_medic.domain.policies.hung_gui import hung_gui_findings

LIMITS = FindingLimits(max_evidence=8, max_affected_processes=5)
WINDOW = (T0 - timedelta(minutes=30), T0)
TREE = build_process_tree(
    process_snapshot(
        process(4, name="explorer.exe"),
        process(10, name="app.exe", parent_pid=4),
        process(11, name="helper.exe", parent_pid=10),
    )
)


def test_windows_of_one_process_make_one_high_confidence_finding() -> None:
    resolved = (
        (HungWindow(10, "Untitled - App"), identity(10)),
        (HungWindow(10, "Settings"), identity(10)),
    )

    (finding,) = hung_gui_findings(
        resolved,
        (),
        tree=TREE,
        protection=PROTECTION,
        ancestry=ANCESTRY,
        window=WINDOW,
        limits=LIMITS,
        max_findings=5,
    )

    assert finding.kind is FindingKind.HUNG_GUI
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence.level is Confidence.HIGH
    assert finding.confidence.raises == (ConfidenceReason.HUNG_WINDOW_REPORTED,)
    assert finding.confidence.lowers == ()
    assert [e.kind for e in finding.evidence] == [EvidenceKind.HUNG_WINDOW] * 2
    assert finding.evidence[0].detail == "window 'Untitled - App' is not responding"
    assert finding.evidence[0].identity == identity(10)
    assert finding.summary == "app.exe (pid 10) is not responding: 2 hung windows"
    assert [a.identity.pid for a in finding.affected_processes] == [10]
    assert [c.action for c in finding.candidate_repairs] == [
        RepairAction.PROCESS_TERMINATE,
        RepairAction.PROCESS_TERMINATE_TREE,
    ]
    assert finding.candidate_repairs[0].eligible is True


def test_a_hung_windows_component_is_reported_with_blocked_candidates() -> None:
    (finding,) = hung_gui_findings(
        ((HungWindow(4, ""), identity(4)),),
        (),
        tree=TREE,
        protection=PROTECTION,
        ancestry=ANCESTRY,
        window=WINDOW,
        limits=LIMITS,
        max_findings=5,
    )

    assert finding.confidence.level is Confidence.HIGH
    assert finding.evidence[0].detail == "window '' is not responding"
    assert finding.summary == "explorer.exe (pid 4) is not responding: 1 hung window"
    assert len(finding.candidate_repairs) == 2  # explorer has children: process and tree scope
    for candidate in finding.candidate_repairs:
        assert candidate.blockers == (RepairBlocker.TARGET_PROTECTED,)
        assert candidate.risk is RiskLevel.HIGH
        assert candidate.eligible is False


def test_windows_whose_owner_could_not_be_verified_are_low_confidence_evidence() -> None:
    (finding,) = hung_gui_findings(
        (),
        (HungWindow(999, "Gone"),),
        tree=TREE,
        protection=PROTECTION,
        ancestry=ANCESTRY,
        window=WINDOW,
        limits=LIMITS,
        max_findings=5,
    )

    assert finding.confidence.level is Confidence.LOW
    assert finding.confidence.raises == (ConfidenceReason.HUNG_WINDOW_REPORTED,)
    assert finding.confidence.lowers == (ConfidenceReason.OWNER_UNVERIFIED,)
    assert finding.evidence[0].detail == "window 'Gone' (reported pid 999) is not responding"
    assert finding.evidence[0].identity is None
    assert finding.summary == "1 hung window whose owner could not be verified"
    assert finding.affected_processes == ()
    assert finding.candidate_repairs == ()


def test_no_hung_windows_means_no_findings() -> None:
    assert (
        hung_gui_findings(
            (),
            (),
            tree=TREE,
            protection=PROTECTION,
            ancestry=ANCESTRY,
            window=WINDOW,
            limits=LIMITS,
            max_findings=5,
        )
        == ()
    )


def test_findings_are_bounded_and_ordered_by_identity() -> None:
    resolved = (
        (HungWindow(11, "b"), identity(11)),
        (HungWindow(10, "a"), identity(10)),
        (HungWindow(4, "c"), identity(4)),
    )

    findings = hung_gui_findings(
        resolved,
        (HungWindow(999, "x"),),
        tree=TREE,
        protection=PROTECTION,
        ancestry=ANCESTRY,
        window=WINDOW,
        limits=LIMITS,
        max_findings=2,
    )

    assert [f.affected_processes[0].identity.pid for f in findings] == [4, 10]
