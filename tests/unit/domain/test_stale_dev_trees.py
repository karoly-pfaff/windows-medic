"""Suspected stale/orphaned development trees: parent evidence first, names never alone."""

from dataclasses import replace
from datetime import timedelta

import pytest

from tests.builders import BOOT, GIB, T0, identity, process, process_snapshot
from tests.containers import ANCESTRY, PROTECTION
from windows_medic.domain.models.evidence import EvidenceKind
from windows_medic.domain.models.finding import (
    Confidence,
    ConfidenceReason,
    Finding,
    FindingKind,
)
from windows_medic.domain.models.incident import Severity
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.repair import RepairAction, RepairScope
from windows_medic.domain.models.tree import build_process_tree
from windows_medic.domain.policies.finding_assembly import FindingLimits
from windows_medic.domain.policies.process_classification import DevelopmentClassifier
from windows_medic.domain.policies.protection import ProtectionPolicy
from windows_medic.domain.policies.resource_hogs import HogThresholds
from windows_medic.domain.policies.risk_markers import RiskMarker
from windows_medic.domain.policies.stale_dev_trees import stale_dev_tree_findings

CLASSIFIER = DevelopmentClassifier(
    process_names=("node.exe", "esbuild.exe", "python.exe"), command_markers=("vite", "npm")
)
LIMITS = FindingLimits(max_evidence=8, max_affected_processes=5)
THRESHOLDS = HogThresholds(cpu_percent=10.0, memory_percent=10.0)
WINDOW = (T0 - timedelta(minutes=30), T0)
STALE_AFTER = timedelta(minutes=30)
OLD = T0 - timedelta(minutes=45)
YOUNG = T0 - timedelta(minutes=5)
GONE_PARENT = 777  # no process with this pid exists in any snapshot below


def findings_for(
    *processes: ProcessObservation,
    protection: ProtectionPolicy = PROTECTION,
    limits: FindingLimits = LIMITS,
    max_findings: int = 5,
) -> tuple[Finding, ...]:
    return stale_dev_tree_findings(
        build_process_tree(process_snapshot(*processes)),
        classifier=CLASSIFIER,
        protection=protection,
        ancestry=ANCESTRY,
        now=T0,
        stale_after=STALE_AFTER,
        thresholds=THRESHOLDS,
        memory_total_bytes=32 * GIB,
        window=WINDOW,
        limits=limits,
        max_findings=max_findings,
    )


def test_aged_orphan_dev_tree_with_several_tools_is_high_confidence() -> None:
    (finding,) = findings_for(
        process(4, name="explorer.exe"),
        process(10, name="node.exe", created=OLD, parent_pid=GONE_PARENT),
        process(11, name="esbuild.exe", created=OLD, parent_pid=10),
        process(12, name="conhost.exe", created=OLD, parent_pid=10),
    )

    assert finding.kind is FindingKind.SUSPECTED_STALE_DEV_TREE
    assert finding.severity is Severity.LOW
    assert finding.confidence.level is Confidence.HIGH
    assert finding.confidence.raises == (
        ConfidenceReason.PARENT_GONE,
        ConfidenceReason.DEVELOPMENT_CLASSIFIER,
        ConfidenceReason.AGE_EXCEEDS_THRESHOLD,
        ConfidenceReason.MULTIPLE_DEVELOPMENT_MEMBERS,
    )
    assert finding.confidence.lowers == ()
    assert [e.kind for e in finding.evidence] == [
        EvidenceKind.UNRESOLVED_PARENT,
        EvidenceKind.DEVELOPMENT_CLASSIFIER,
        EvidenceKind.PROCESS_AGE,
        EvidenceKind.TREE_MEMBERS,
    ]
    assert finding.evidence[0].detail == "parent pid 777 no longer exists"
    assert finding.evidence[0].identity == identity(10, OLD)
    assert finding.evidence[1].detail == "matches development classifier: name node.exe"
    assert finding.evidence[2].detail == "running for 45 min (stale after 30 min)"
    assert finding.evidence[2].value == 45.0
    assert (
        finding.evidence[3].detail
        == "2 descendants, 1 further development tool, 300 MiB working set"
    )
    assert finding.evidence[3].value == 2.0
    assert finding.summary == (
        "node.exe (pid 10) and 2 descendants: parent gone, development tooling, running for 45 min"
    )
    assert [a.identity.pid for a in finding.affected_processes] == [10, 11]
    assert finding.affected_processes[0].risk_markers == (RiskMarker.UNRESOLVED_PARENT,)
    assert [(c.action, c.scope) for c in finding.candidate_repairs] == [
        (RepairAction.PROCESS_TERMINATE, RepairScope.PROCESS),
        (RepairAction.PROCESS_TERMINATE_TREE, RepairScope.TREE),
    ]
    assert finding.candidate_repairs[1].eligible is True
    assert finding.candidate_repairs[1].evidence == finding.evidence


def test_a_development_name_with_a_live_parent_is_not_an_orphan() -> None:
    findings = findings_for(
        process(4, name="explorer.exe"),
        process(10, name="node.exe", created=OLD, parent_pid=4),
        process(11, name="esbuild.exe", created=OLD, parent_pid=10),
    )

    assert findings == ()


def test_a_reused_parent_pid_counts_as_validated_parent_evidence() -> None:
    (finding,) = findings_for(
        process(5, name="pwsh.exe", created=T0 - timedelta(minutes=1)),
        process(10, name="node.exe", created=OLD, parent_pid=5),
    )

    assert finding.confidence.level is Confidence.MEDIUM
    assert finding.confidence.raises[0] is ConfidenceReason.PARENT_PID_REUSED
    assert finding.evidence[0].detail == "parent pid 5 now belongs to a newer process"
    assert finding.summary.endswith("parent pid reused, development tooling, running for 45 min")
    assert [(c.action, c.eligible) for c in finding.candidate_repairs] == [
        (RepairAction.PROCESS_TERMINATE, True)
    ]


def test_an_orphan_that_is_not_development_tooling_is_not_reported() -> None:
    findings = findings_for(process(10, name="notepad.exe", created=OLD, parent_pid=GONE_PARENT))

    assert findings == ()


def test_a_young_orphan_is_low_confidence_with_no_recommendation() -> None:
    (finding,) = findings_for(process(10, name="node.exe", created=YOUNG, parent_pid=GONE_PARENT))

    assert finding.confidence.level is Confidence.LOW
    assert finding.confidence.lowers == (ConfidenceReason.RECENTLY_STARTED,)
    assert finding.candidate_repairs == ()


def test_a_protected_root_is_never_a_stale_dev_tree() -> None:
    guarded = replace(PROTECTION, user_protected_names=("node.exe",))

    findings = findings_for(
        process(10, name="node.exe", created=OLD, parent_pid=GONE_PARENT), protection=guarded
    )

    assert findings == ()


def test_a_protected_member_lowers_confidence_and_blocks_the_tree_candidate() -> None:
    (finding,) = findings_for(
        process(10, name="node.exe", created=OLD, parent_pid=GONE_PARENT),
        process(11, name="esbuild.exe", created=OLD, parent_pid=10),
        process(12, name="lsass.exe", created=OLD, parent_pid=10),
    )

    assert finding.confidence.level is Confidence.LOW
    assert finding.confidence.lowers == (ConfidenceReason.PROTECTED_MEMBER,)
    assert finding.evidence[-1].kind is EvidenceKind.RISK_MARKER
    assert finding.candidate_repairs == ()


def test_an_unknown_parent_is_not_validated_evidence() -> None:
    findings = findings_for(
        process(
            10,
            name="node.exe",
            created=OLD,
            parent_pid=Unavailable(UnavailableReason.ACCESS_DENIED),
        )
    )

    assert findings == ()


def test_command_line_markers_classify_the_root_as_well() -> None:
    root = replace(
        process(10, name="MyRunner.exe", created=OLD, parent_pid=GONE_PARENT),
        command_line=("MyRunner.exe", "C:\\proj\\node_modules\\vite\\bin\\vite.js"),
    )

    (finding,) = findings_for(root)

    assert finding.evidence[1].detail == "matches development classifier: markers vite"


def test_a_large_tree_is_medium_severity() -> None:
    (finding,) = findings_for(
        process(10, name="node.exe", created=OLD, parent_pid=GONE_PARENT),
        process(11, name="node.exe", created=OLD, parent_pid=10, working_set_bytes=4 * GIB),
    )

    assert finding.severity is Severity.MEDIUM
    assert (
        finding.evidence[3].detail
        == "1 descendant, 1 further development tool, 4196 MiB working set"
    )


def test_findings_and_affected_processes_are_bounded() -> None:
    processes = [
        process(pid, name="python.exe", created=OLD, parent_pid=GONE_PARENT) for pid in (10, 20, 30)
    ] + [process(pid, name="esbuild.exe", created=OLD, parent_pid=10) for pid in range(11, 19)]

    findings = findings_for(
        *processes, max_findings=2, limits=FindingLimits(max_evidence=8, max_affected_processes=3)
    )

    assert [f.affected_processes[0].identity.pid for f in findings] == [10, 20]
    assert [a.identity.pid for a in findings[0].affected_processes] == [10, 11, 12]
    assert findings[0].confidence.level is Confidence.HIGH
    assert identity(30, OLD) not in {a.identity for f in findings for a in f.affected_processes}
    assert BOOT < OLD


def test_memory_total_must_be_positive() -> None:
    with pytest.raises(ValueError, match="memory_total_bytes"):
        stale_dev_tree_findings(
            build_process_tree(process_snapshot()),
            classifier=CLASSIFIER,
            protection=PROTECTION,
            ancestry=ANCESTRY,
            now=T0,
            stale_after=STALE_AFTER,
            thresholds=THRESHOLDS,
            memory_total_bytes=0,
            window=WINDOW,
            limits=LIMITS,
            max_findings=1,
        )
