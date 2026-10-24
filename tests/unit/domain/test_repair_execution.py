"""Repair execution policy: ordering, outcome mapping, status and identity drift. Pure."""

from datetime import timedelta

import pytest

from tests.builders import BOOT, T0, identity, process, process_snapshot
from windows_medic.domain.models.repair import (
    MemberOutcome,
    MemberResult,
    RejectionReason,
    RepairBlocker,
    RepairStatus,
    TerminationAttempt,
    TerminationOutcome,
)
from windows_medic.domain.models.tree import Descendant, build_process_tree
from windows_medic.domain.policies.repair_execution import (
    appeared_since,
    member_outcome,
    rejection_for,
    repair_status,
    termination_order,
)


def member(pid: int, outcome: MemberOutcome, depth: int = 0) -> MemberResult:
    return MemberResult(identity(pid), "p.exe", depth, outcome, None)


class TestTerminationOrder:
    def test_children_come_before_parents_and_the_target_last(self) -> None:
        tree = build_process_tree(
            process_snapshot(
                process(1),
                process(2, parent_pid=1),
                process(3, parent_pid=1),
                process(4, parent_pid=3),
                process(5, parent_pid=4),
            )
        )

        ordered = termination_order(identity(1), tree.descendants_of(identity(1)))

        # Parents first: a supervisor (nodemon, uvicorn --reload) is gone before its
        # children, so it cannot respawn them while the rest are being terminated.
        assert [(m.identity.pid, m.depth) for m in ordered] == [
            (1, 0),
            (2, 1),
            (3, 1),
            (4, 2),
            (5, 3),
        ]

    def test_a_leaf_target_is_the_only_member(self) -> None:
        assert [m.identity.pid for m in termination_order(identity(9), ())] == [9]

    def test_equal_depth_orders_by_identity_for_determinism(self) -> None:
        descendants = (Descendant(identity(7), 1), Descendant(identity(3), 1))

        ordered = termination_order(identity(1), descendants)

        assert [m.identity.pid for m in ordered] == [1, 3, 7]


class TestRejection:
    @pytest.mark.parametrize(
        ("blockers", "expected"),
        [
            ((RepairBlocker.TARGET_PROTECTED,), RejectionReason.TARGET_PROTECTED),
            ((RepairBlocker.TREE_CONTAINS_PROTECTED,), RejectionReason.TREE_CONTAINS_PROTECTED),
            (
                (RepairBlocker.TARGET_PROTECTED, RepairBlocker.TREE_CONTAINS_PROTECTED),
                RejectionReason.TARGET_PROTECTED,
            ),
        ],
    )
    def test_the_first_blocker_is_the_rejection_reason(
        self, blockers: tuple[RepairBlocker, ...], expected: RejectionReason
    ) -> None:
        assert rejection_for(blockers) is expected

    def test_no_blockers_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError, match="blocker"):
            rejection_for(())


class TestMemberOutcome:
    @pytest.mark.parametrize(
        ("attempt", "gone", "expected"),
        [
            (TerminationOutcome.SIGNALLED, True, MemberOutcome.TERMINATED),
            (TerminationOutcome.SIGNALLED, False, MemberOutcome.STILL_RUNNING),
            (TerminationOutcome.ALREADY_GONE, True, MemberOutcome.ALREADY_GONE),
            (TerminationOutcome.IDENTITY_MISMATCH, True, MemberOutcome.ALREADY_GONE),
            (TerminationOutcome.ACCESS_DENIED, False, MemberOutcome.ACCESS_DENIED),
            (TerminationOutcome.ACCESS_DENIED, True, MemberOutcome.ALREADY_GONE),
            (TerminationOutcome.ERROR, False, MemberOutcome.ERROR),
            (TerminationOutcome.ERROR, True, MemberOutcome.ALREADY_GONE),
        ],
    )
    def test_the_verified_state_decides_the_outcome(
        self, attempt: TerminationOutcome, gone: bool, expected: MemberOutcome
    ) -> None:
        assert member_outcome(TerminationAttempt(attempt, None), gone=gone) is expected

    def test_a_reused_pid_is_never_signalled_and_reads_as_gone(self) -> None:
        # The controller saw a different create time behind the PID: the planned process
        # is gone, whatever now holds its PID was not touched.
        outcome = member_outcome(
            TerminationAttempt(TerminationOutcome.IDENTITY_MISMATCH), gone=False
        )

        assert outcome is MemberOutcome.ALREADY_GONE


class TestStatus:
    def test_everything_gone_is_success(self) -> None:
        members = (member(2, MemberOutcome.TERMINATED, 1), member(1, MemberOutcome.ALREADY_GONE))

        assert repair_status(members) is RepairStatus.SUCCEEDED

    def test_nothing_gone_is_failure(self) -> None:
        members = (
            member(2, MemberOutcome.ACCESS_DENIED, 1),
            member(1, MemberOutcome.STILL_RUNNING),
        )

        assert repair_status(members) is RepairStatus.FAILED

    def test_a_mix_is_partial(self) -> None:
        members = (member(2, MemberOutcome.TERMINATED, 1), member(1, MemberOutcome.ERROR))

        assert repair_status(members) is RepairStatus.PARTIAL

    def test_no_members_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError, match="member"):
            repair_status(())


class TestIdentityDrift:
    def test_children_spawned_by_planned_members_after_the_plan_are_reported(self) -> None:
        planned = {identity(1), identity(2)}
        later = T0 + timedelta(seconds=1)
        after = process_snapshot(
            process(3, parent_pid=1, created=later),  # spawned by the target after planning
            process(4, parent_pid=2, created=BOOT),  # existed before: was simply not planned
            process(5, parent_pid=9, created=later),  # unrelated
            observed_at=later,
        )

        appeared = appeared_since(planned, after, since=T0)

        assert appeared == (identity(3, later),)

    def test_planned_members_themselves_are_never_drift(self) -> None:
        planned = {identity(1)}
        after = process_snapshot(process(1, parent_pid=1, created=BOOT))

        assert appeared_since(planned, after, since=BOOT) == ()
