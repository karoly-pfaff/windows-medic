"""Repair planning: candidates for terminating a process or its tree, never executed here."""

from tests.builders import identity, process, process_snapshot
from tests.containers import ANCESTRY, PROTECTION
from windows_medic.domain.models.evidence import Evidence, EvidenceKind
from windows_medic.domain.models.repair import (
    RepairAction,
    RepairBlocker,
    RepairScope,
    RiskLevel,
)
from windows_medic.domain.models.tree import build_process_tree
from windows_medic.domain.policies.repair_planning import plan_termination

EVIDENCE = (Evidence(EvidenceKind.PROCESS_AGE, "age 45 min", value=45.0),)


def test_a_leaf_process_gets_one_low_risk_candidate() -> None:
    tree = build_process_tree(process_snapshot(process(4, name="explorer.exe"), process(10)))

    candidates = plan_termination(
        identity(10), tree, protection=PROTECTION, ancestry=ANCESTRY, evidence=EVIDENCE
    )

    assert [c.action for c in candidates] == [RepairAction.PROCESS_TERMINATE]
    assert candidates[0].target == identity(10)
    assert candidates[0].scope is RepairScope.PROCESS
    assert candidates[0].risk is RiskLevel.LOW
    assert candidates[0].eligible is True
    assert candidates[0].requires_elevation is False
    assert candidates[0].evidence == EVIDENCE


def test_a_process_with_children_also_gets_a_tree_candidate() -> None:
    tree = build_process_tree(
        process_snapshot(process(10), process(11, parent_pid=10), process(12, parent_pid=11))
    )

    candidates = plan_termination(
        identity(10), tree, protection=PROTECTION, ancestry=ANCESTRY, evidence=EVIDENCE
    )

    assert [c.action for c in candidates] == [
        RepairAction.PROCESS_TERMINATE,
        RepairAction.PROCESS_TERMINATE_TREE,
    ]
    assert candidates[1].scope is RepairScope.TREE
    assert candidates[1].eligible is True


def test_protected_members_block_the_tree_candidate_only() -> None:
    tree = build_process_tree(
        process_snapshot(process(10), process(11, name="lsass.exe", parent_pid=10))
    )

    candidates = plan_termination(
        identity(10), tree, protection=PROTECTION, ancestry=ANCESTRY, evidence=EVIDENCE
    )

    assert candidates[0].blockers == ()
    assert candidates[1].blockers == (RepairBlocker.TREE_CONTAINS_PROTECTED,)
    assert candidates[1].risk is RiskLevel.HIGH


def test_a_protected_target_is_reported_as_blocked_not_omitted() -> None:
    tree = build_process_tree(process_snapshot(process(4242, name="windows-medic.exe")))

    (candidate,) = plan_termination(
        identity(4242), tree, protection=PROTECTION, ancestry=ANCESTRY, evidence=EVIDENCE
    )

    assert candidate.blockers == (RepairBlocker.TARGET_PROTECTED,)
    assert candidate.risk is RiskLevel.HIGH
    assert candidate.eligible is False


def test_terminal_ancestry_raises_risk_to_medium() -> None:
    tree = build_process_tree(
        process_snapshot(process(1, name="pwsh.exe"), process(10, parent_pid=1))
    )

    (candidate,) = plan_termination(
        identity(10), tree, protection=PROTECTION, ancestry=ANCESTRY, evidence=EVIDENCE
    )

    assert candidate.risk is RiskLevel.MEDIUM
    assert candidate.eligible is True
