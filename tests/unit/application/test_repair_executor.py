"""RepairExecutor: identity revalidation, policy rejection, ordered termination, verification."""

import io
import json
import logging
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta

import pytest

from tests.builders import BOOT, T0, identity, process
from tests.containers import ANCESTRY, PROTECTION
from tests.fakes import FakeClock, FakeProcessWorld, FakeRepairAudit
from windows_medic.application.services.repair_audit_trail import RepairAuditTrail
from windows_medic.application.services.repair_executor import (
    RepairExecutor,
    RepairLimits,
    RepairRequest,
)
from windows_medic.domain.errors import RepairAuditError
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.repair import (
    MemberOutcome,
    RejectionReason,
    RepairAction,
    RepairScope,
    RepairStatus,
    RiskLevel,
    TerminationAttempt,
    Verification,
)
from windows_medic.infrastructure.config.settings import LogLevel
from windows_medic.infrastructure.observability.structured_logging import configure_logging

LIMITS = RepairLimits(
    verify_timeout=timedelta(seconds=2),
    verify_interval=timedelta(milliseconds=100),
    max_tree_members=5,
)
NEW = BOOT + timedelta(hours=1)


def build(
    *processes: ProcessObservation, limits: RepairLimits = LIMITS
) -> tuple[RepairExecutor, FakeProcessWorld, FakeRepairAudit, FakeClock]:
    clock = FakeClock(T0)
    world = FakeProcessWorld(clock, *processes)
    audit = FakeRepairAudit()
    ids = iter(f"rep-{n}" for n in range(1, 100))
    executor = RepairExecutor(
        process_reader=world,
        controller=world,
        trail=RepairAuditTrail(
            audit=audit, clock=clock, retention=timedelta(days=30), ids=lambda: next(ids)
        ),
        protection=PROTECTION,
        ancestry=ANCESTRY,
        limits=limits,
    )
    return executor, world, audit, clock


def terminate(pid: int, scope: RepairScope = RepairScope.PROCESS) -> RepairRequest:
    action = (
        RepairAction.PROCESS_TERMINATE
        if scope is RepairScope.PROCESS
        else RepairAction.PROCESS_TERMINATE_TREE
    )
    return RepairRequest(action=action, scope=scope, targets=(identity(pid),))


TREE = (
    process(4, name="explorer.exe"),
    process(10, name="node.exe", parent_pid=4),
    process(11, name="esbuild.exe", parent_pid=10),
    process(12, name="node.exe", parent_pid=11),
)


class TestSuccess:
    def test_a_single_process_is_terminated_verified_and_audited(self) -> None:
        executor, world, audit, clock = build(*TREE)

        record = executor.execute(terminate(11))

        assert record.status is RepairStatus.SUCCEEDED
        assert record.id == "rep-1"
        assert record.action is RepairAction.PROCESS_TERMINATE
        assert record.target == identity(11)
        assert record.risk is RiskLevel.LOW
        assert record.requires_elevation is False
        assert record.rejection is None
        assert [(m.identity.pid, m.depth, m.outcome) for m in record.members] == [
            (11, 0, MemberOutcome.TERMINATED)
        ]
        assert record.members[0].name == "esbuild.exe"
        assert record.appeared == ()
        assert record.verification == Verification(True, "1 of 1 members gone", T0)
        assert record.requested_at == T0
        assert record.completed_at == T0
        assert world.terminations == [identity(11)]
        assert identity(11) not in world.live
        assert [r.status for r in audit.saves] == [RepairStatus.STARTED, RepairStatus.SUCCEEDED]
        assert audit.saves[0].id == audit.saves[1].id == "rep-1"
        assert audit.purged_before == [T0 - timedelta(days=30)]
        assert clock.sleeps == []

    def test_a_tree_is_terminated_parents_first_with_depths(self) -> None:
        executor, world, _, _ = build(*TREE)

        record = executor.execute(terminate(10, RepairScope.TREE))

        assert record.status is RepairStatus.SUCCEEDED
        assert world.terminations == [identity(10), identity(11), identity(12)]
        assert [(m.identity.pid, m.depth) for m in record.members] == [(10, 0), (11, 1), (12, 2)]
        assert all(m.outcome is MemberOutcome.TERMINATED for m in record.members)
        assert record.verification is not None
        assert record.verification.detail == "3 of 3 members gone"
        assert identity(4) in world.live

    def test_the_whole_repair_runs_under_the_trails_exclusive_lock(self) -> None:
        executor, world, _, _ = build(*TREE)
        held_while_terminating: list[bool] = []
        original = world.terminate

        def observing(identity: ProcessIdentity) -> TerminationAttempt:
            held_while_terminating.append(executor.trail.exclusive.locked())
            return original(identity)

        world.terminate = observing  # type: ignore[method-assign]

        executor.execute(terminate(11))

        assert held_while_terminating == [True]
        assert not executor.trail.exclusive.locked()

    def test_a_verification_that_cannot_observe_is_recorded_as_unverified_failure(self) -> None:
        executor, world, audit, _ = build(*TREE)
        world.fail_from_snapshot = 2  # the plan reads fine, verification cannot

        record = executor.execute(terminate(10, RepairScope.TREE))

        assert world.terminations == [identity(10), identity(11), identity(12)]
        assert record.status is RepairStatus.FAILED
        assert all(m.outcome is MemberOutcome.UNVERIFIED for m in record.members)
        assert record.verification is not None
        assert record.verification.passed is False
        assert "could not verify" in record.verification.detail
        assert "scripted" in record.verification.detail
        # The audit is never left at `started` after a mutation.
        assert [s.status for s in audit.saves] == [RepairStatus.STARTED, RepairStatus.FAILED]

    def test_verification_polls_until_the_process_is_really_gone(self) -> None:
        executor, world, _, clock = build(*TREE)
        world.stubborn[identity(11)] = 3  # gone only at the third snapshot after the signal

        record = executor.execute(terminate(11))

        assert record.status is RepairStatus.SUCCEEDED
        assert record.members[0].outcome is MemberOutcome.TERMINATED
        assert clock.sleeps == [0.1, 0.1]


class TestRejection:
    def test_a_stale_identity_is_rejected_before_any_os_call(self) -> None:
        executor, world, audit, _ = build(process(11, name="node.exe", created=NEW))

        record = executor.execute(terminate(11))

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.STALE_IDENTITY
        assert record.members == ()
        assert record.risk is None
        assert record.completed_at == T0
        assert world.terminations == []
        assert [r.status for r in audit.saves] == [RepairStatus.REJECTED]

    def test_a_missing_process_is_rejected(self) -> None:
        executor, world, _, _ = build(*TREE)

        record = executor.execute(terminate(99))

        assert record.rejection is RejectionReason.TARGET_NOT_FOUND
        assert world.terminations == []

    @pytest.mark.parametrize("name", ["lsass.exe", "windows-medic-agent.exe", "explorer.exe"])
    def test_a_protected_target_is_rejected_by_policy_before_the_os(self, name: str) -> None:
        executor, world, _, _ = build(process(50, name=name))

        record = executor.execute(terminate(50))

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.TARGET_PROTECTED
        assert record.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert world.terminations == []

    def test_a_tree_with_a_protected_member_is_rejected_as_a_tree_but_not_as_a_process(
        self,
    ) -> None:
        executor, world, _, _ = build(
            process(10, name="node.exe"), process(11, name="lsass.exe", parent_pid=10)
        )

        as_tree = executor.execute(terminate(10, RepairScope.TREE))
        as_process = executor.execute(terminate(10))

        assert as_tree.rejection is RejectionReason.TREE_CONTAINS_PROTECTED
        assert as_process.status is RepairStatus.SUCCEEDED
        assert world.terminations == [identity(10)]

    def test_an_oversized_tree_is_rejected(self) -> None:
        processes = [process(10, name="node.exe")] + [
            process(pid, name="node.exe", parent_pid=10) for pid in range(11, 17)
        ]
        executor, world, _, _ = build(*processes)

        record = executor.execute(terminate(10, RepairScope.TREE))

        assert record.rejection is RejectionReason.TREE_TOO_LARGE
        assert world.terminations == []


class TestPartialAndFailed:
    def test_denied_members_are_reported_and_the_repair_is_partial(self) -> None:
        executor, world, _, _ = build(*TREE)
        world.denied.add(identity(12))

        record = executor.execute(terminate(10, RepairScope.TREE))

        assert record.status is RepairStatus.PARTIAL
        assert [(m.identity.pid, m.outcome) for m in record.members] == [
            (10, MemberOutcome.TERMINATED),
            (11, MemberOutcome.TERMINATED),
            (12, MemberOutcome.ACCESS_DENIED),
        ]
        assert record.members[2].detail == "access is denied"
        assert record.verification is not None
        assert record.verification.passed is False
        assert record.verification.detail == "2 of 3 members gone; still running: pid 12"

    def test_a_process_that_will_not_die_fails_within_the_bounded_timeout(self) -> None:
        executor, world, _, clock = build(*TREE)
        world.stubborn[identity(11)] = 1000

        record = executor.execute(terminate(11))

        assert record.status is RepairStatus.FAILED
        assert record.members[0].outcome is MemberOutcome.STILL_RUNNING
        assert len(clock.sleeps) == 20
        assert clock.now() == T0 + timedelta(seconds=2)

    def test_an_os_error_is_reported_with_its_detail(self) -> None:
        executor, world, _, _ = build(*TREE)
        world.failing[identity(11)] = "[WinError 6] The handle is invalid"

        record = executor.execute(terminate(11))

        assert record.status is RepairStatus.FAILED
        assert record.members[0].outcome is MemberOutcome.ERROR
        assert record.members[0].detail == "[WinError 6] The handle is invalid"

    def test_a_process_that_exits_on_its_own_counts_as_gone(self) -> None:
        executor, world, _, _ = build(*TREE)
        world.vanish_after_plan.add(identity(12))  # exits between the snapshot and the OS call

        record = executor.execute(terminate(10, RepairScope.TREE))

        assert record.status is RepairStatus.SUCCEEDED
        assert [m.outcome for m in record.members] == [
            MemberOutcome.TERMINATED,
            MemberOutcome.TERMINATED,
            MemberOutcome.ALREADY_GONE,
        ]


class TestIdentityDrift:
    def test_children_spawned_during_a_tree_teardown_are_reported_not_hidden(self) -> None:
        executor, world, _, _ = build(*TREE)
        spawned = process(13, name="node.exe", parent_pid=10, created=T0)
        world.spawns[identity(11)] = spawned  # the parent reacts to losing a child

        record = executor.execute(terminate(10, RepairScope.TREE))

        assert record.status is RepairStatus.PARTIAL
        assert record.appeared == (identity(13, T0),)
        assert record.verification is not None
        assert record.verification.passed is False
        assert record.verification.detail == (
            "3 of 3 members gone; appeared after the plan and not targeted: pid 13"
        )

    def test_drift_is_informational_for_a_single_process_repair(self) -> None:
        executor, world, _, _ = build(*TREE)
        world.spawns[identity(11)] = process(13, name="node.exe", parent_pid=11, created=T0)

        record = executor.execute(terminate(11))

        assert record.status is RepairStatus.SUCCEEDED
        assert record.appeared == (identity(13, T0),)
        assert record.verification is not None
        assert record.verification.passed is True


class TestAudit:
    def test_the_intended_action_is_recorded_before_any_mutation(self) -> None:
        executor, world, audit, _ = build(*TREE)
        audit.fail_saves.add(1)

        with pytest.raises(RepairAuditError, match="locked"):
            executor.execute(terminate(11))

        assert world.terminations == []
        assert identity(11) in world.live

    @pytest.fixture
    def log_stream(self) -> Iterator[io.StringIO]:
        root = logging.getLogger()
        saved_handlers, saved_level = list(root.handlers), root.level
        stream = io.StringIO()
        configure_logging(LogLevel.INFO, stream)
        yield stream
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)

    def test_a_failing_final_write_is_logged_and_the_result_still_returned(
        self, log_stream: io.StringIO
    ) -> None:
        executor, world, audit, _ = build(*TREE)
        audit.fail_saves.add(2)

        record = executor.execute(terminate(11))

        assert record.status is RepairStatus.SUCCEEDED
        assert identity(11) not in world.live
        events = [json.loads(line)["event"] for line in log_stream.getvalue().splitlines()]
        assert events == ["repair.started", "repair.completed", "repair.audit_failed"]

    def test_rejections_are_audited_too(self, log_stream: io.StringIO) -> None:
        executor, _, audit, _ = build(process(50, name="lsass.exe"))

        executor.execute(terminate(50))

        assert audit.records["rep-1"].status is RepairStatus.REJECTED
        events = [json.loads(line)["event"] for line in log_stream.getvalue().splitlines()]
        assert events == ["repair.rejected"]


class TestRequests:
    def test_several_targets_share_one_record(self) -> None:
        executor, world, _, _ = build(*TREE)
        request = RepairRequest(
            action=RepairAction.PORT_CLEAR,
            scope=RepairScope.PROCESS,
            targets=(identity(11), identity(12)),
            port=3000,
        )

        record = executor.execute(request)

        assert record.status is RepairStatus.SUCCEEDED
        assert record.action is RepairAction.PORT_CLEAR
        assert record.port == 3000
        assert record.target == identity(11)
        assert [m.identity.pid for m in record.members] == [11, 12]
        assert world.terminations == [identity(11), identity(12)]

    def test_a_postcondition_can_downgrade_a_successful_termination(self) -> None:
        executor, _, _, _ = build(*TREE)

        record = executor.execute(
            terminate(11),
            postcondition=lambda: Verification(False, "port 3000 still has a listener", T0),
        )

        assert record.status is RepairStatus.PARTIAL
        assert record.verification is not None
        assert record.verification.passed is False
        assert record.verification.detail == ("1 of 1 members gone; port 3000 still has a listener")

    def test_elevation_needs_are_reported(self) -> None:
        executor, world, _, _ = build(replace(process(60, name="svc.exe"), session_id=0))
        world.denied.add(identity(60))

        record = executor.execute(terminate(60))

        assert record.status is RepairStatus.FAILED
        assert record.requires_elevation is True
        assert record.risk is RiskLevel.MEDIUM
        assert record.members[0].outcome is MemberOutcome.ACCESS_DENIED

    def test_a_request_needs_at_least_one_target(self) -> None:
        with pytest.raises(ValueError, match="target"):
            RepairRequest(
                action=RepairAction.PROCESS_TERMINATE, scope=RepairScope.PROCESS, targets=()
            )

    def test_retention_is_validated(self) -> None:
        with pytest.raises(ValueError, match="retention"):
            RepairAuditTrail(audit=FakeRepairAudit(), clock=FakeClock(T0), retention=timedelta(0))


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"verify_timeout": timedelta(seconds=-1)}, "verify_timeout"),
        ({"max_tree_members": 0}, "max_tree_members"),
        ({"verify_interval": timedelta(0)}, "verify_interval"),
    ],
)
def test_every_limit_is_validated(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        replace(LIMITS, **overrides)  # type: ignore[arg-type]


def test_overlapping_targets_share_members_once() -> None:
    executor, world, _, _ = build(*TREE)
    request = RepairRequest(
        action=RepairAction.PROCESS_TERMINATE_TREE,
        scope=RepairScope.TREE,
        targets=(identity(10), identity(11)),
    )

    record = executor.execute(request)

    assert record.status is RepairStatus.SUCCEEDED
    assert [m.identity.pid for m in record.members] == [10, 11, 12]
    assert world.terminations == [identity(10), identity(11), identity(12)]
