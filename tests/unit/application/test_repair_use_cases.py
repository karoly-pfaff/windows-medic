"""TerminateProcess, ClearPort and ListRecentRepairs over the executor and fakes."""

from datetime import timedelta

import pytest

from tests.builders import BOOT, T0, identity, listener, process
from tests.containers import ANCESTRY, PROTECTION
from tests.fakes import FakeClock, FakeProcessWorld, FakeRepairAudit, FakeWorldNetworkReader
from windows_medic.application.services.repair_audit_trail import RepairAuditTrail
from windows_medic.application.services.repair_executor import RepairExecutor, RepairLimits
from windows_medic.application.use_cases.clear_port import ClearPort
from windows_medic.application.use_cases.inspect_port import InspectPort
from windows_medic.application.use_cases.inspect_process import InspectionLimits
from windows_medic.application.use_cases.list_recent_repairs import (
    ListRecentRepairs,
    RepairListLimits,
)
from windows_medic.application.use_cases.terminate_process import TerminateProcess
from windows_medic.domain.models.network import ListeningEndpoint
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.repair import (
    MemberOutcome,
    RejectionReason,
    RepairAction,
    RepairScope,
    RepairStatus,
)

LIMITS = RepairLimits(
    verify_timeout=timedelta(seconds=2),
    verify_interval=timedelta(milliseconds=100),
    max_tree_members=50,
)


class Harness:
    def __init__(
        self,
        *processes: ProcessObservation,
        listeners: tuple[ListeningEndpoint, ...] = (),
        later: tuple[ListeningEndpoint, ...] | None = None,
    ) -> None:
        self.clock = FakeClock(T0)
        self.world = FakeProcessWorld(self.clock, *processes)
        self.audit = FakeRepairAudit()
        self.network = FakeWorldNetworkReader(self.world, *listeners, later=later)
        ids = iter(f"rep-{n}" for n in range(1, 100))
        self.trail = RepairAuditTrail(
            audit=self.audit,
            clock=self.clock,
            retention=timedelta(days=30),
            ids=lambda: next(ids),
        )
        self.executor = RepairExecutor(
            process_reader=self.world,
            controller=self.world,
            trail=self.trail,
            protection=PROTECTION,
            ancestry=ANCESTRY,
            limits=LIMITS,
        )
        self.terminate = TerminateProcess(executor=self.executor)
        self.clear_port = ClearPort(
            inspect_port=InspectPort(
                process_reader=self.world,
                network_reader=self.network,
                protection=PROTECTION,
                ancestry=ANCESTRY,
                limits=InspectionLimits(max_ancestors=4, max_descendants=4, max_port_owners=2),
            ),
            network_reader=self.network,
            executor=self.executor,
        )
        self.list_repairs = ListRecentRepairs(self.audit, RepairListLimits(max_limit=5))


TREE = (
    process(4, name="explorer.exe"),
    process(10, name="node.exe", parent_pid=4),
    process(11, name="esbuild.exe", parent_pid=10),
)


class TestTerminateProcess:
    def test_terminates_exactly_the_requested_identity(self) -> None:
        h = Harness(*TREE)

        record = h.terminate.execute(10, BOOT)

        assert record.status is RepairStatus.SUCCEEDED
        assert record.action is RepairAction.PROCESS_TERMINATE
        assert h.world.terminations == [identity(10)]
        assert identity(11) in h.world.live

    def test_tree_scope_uses_the_tree_recipe(self) -> None:
        h = Harness(*TREE)

        record = h.terminate.execute(10, BOOT, RepairScope.TREE)

        assert record.action is RepairAction.PROCESS_TERMINATE_TREE
        assert h.world.terminations == [identity(10), identity(11)]

    def test_a_wrong_create_time_never_reaches_the_os(self) -> None:
        h = Harness(*TREE)

        record = h.terminate.execute(10, BOOT + timedelta(seconds=1))

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.STALE_IDENTITY
        assert h.world.terminations == []

    def test_boundary_validation_is_a_value_error(self) -> None:
        h = Harness(*TREE)

        with pytest.raises(ValueError, match="pid"):
            h.terminate.execute(-1, BOOT)


class TestClearPort:
    def test_terminates_the_confirmed_owner_and_verifies_the_port_is_free(self) -> None:
        h = Harness(*TREE, listeners=(listener(3000, 11),))

        record = h.clear_port.execute(3000)

        assert record.status is RepairStatus.SUCCEEDED
        assert record.action is RepairAction.PORT_CLEAR
        assert record.port == 3000
        assert record.target == identity(11)
        assert [m.identity for m in record.members] == [identity(11)]
        assert record.verification is not None
        assert record.verification.passed is True
        assert record.verification.detail == "1 of 1 members gone; port 3000 has no listener"
        assert h.world.terminations == [identity(11)]
        assert h.network.calls == 2  # once to resolve the owner, once to verify

    def test_nothing_listening_is_rejected_without_an_os_call(self) -> None:
        h = Harness(*TREE)

        record = h.clear_port.execute(3000)

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.PORT_NOT_LISTENING
        assert record.target is None
        assert record.port == 3000
        assert h.world.terminations == []
        assert h.audit.records["rep-1"].status is RepairStatus.REJECTED

    def test_a_protected_owner_is_rejected_by_policy(self) -> None:
        h = Harness(*TREE, listeners=(listener(445, 4),))

        record = h.clear_port.execute(445)

        assert record.rejection is RejectionReason.PORT_OWNER_PROTECTED
        assert record.target == identity(4)
        assert h.world.terminations == []

    def test_an_unresolved_owner_is_rejected(self) -> None:
        h = Harness(*TREE, listeners=(listener(3000, None),))

        record = h.clear_port.execute(3000)

        assert record.rejection is RejectionReason.PORT_OWNER_UNRESOLVED
        assert h.world.terminations == []

    def test_the_planned_owner_must_still_own_the_port(self) -> None:
        h = Harness(*TREE, listeners=(listener(3000, 11),))

        record = h.clear_port.execute(3000, expected_owner=identity(10))

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.PORT_OWNER_CHANGED
        assert record.target == identity(10)
        assert h.world.terminations == []

    def test_a_listener_that_survives_fails_the_postcondition(self) -> None:
        h = Harness(*TREE, listeners=(listener(3000, 11),))
        h.world.stubborn[identity(11)] = 1000

        record = h.clear_port.execute(3000)

        assert record.status is RepairStatus.FAILED
        assert record.members[0].outcome is MemberOutcome.STILL_RUNNING
        assert record.verification is not None
        assert record.verification.detail == (
            "0 of 1 members gone; still running: pid 11; port 3000 still has a listener (pid 11)"
        )

    def test_a_new_owner_after_termination_is_reported_distinctly(self) -> None:
        h = Harness(*TREE, listeners=(listener(3000, 11), listener(3000, 10)))
        # Two owners share the port (parent and child); the child dies, the parent refuses.
        h.world.denied.add(identity(10))

        record = h.clear_port.execute(3000)

        assert record.status is RepairStatus.PARTIAL
        assert record.verification is not None
        assert record.verification.detail.endswith("port 3000 still has a listener (pid 10)")

    def test_an_owner_that_appears_later_is_owner_changed(self) -> None:
        # The inspection sees pid 11; by verification time another process listens.
        h = Harness(*TREE, listeners=(listener(3000, 11),), later=(listener(3000, 4),))

        record = h.clear_port.execute(3000)

        assert record.status is RepairStatus.PARTIAL
        assert record.verification is not None
        assert record.verification.detail.endswith(
            "port 3000 is now listened on by a different owner (pid 4)"
        )

    def test_port_range_is_validated(self) -> None:
        with pytest.raises(ValueError, match="port"):
            Harness(*TREE).clear_port.execute(70000)


class TestListRecentRepairs:
    def test_lists_newest_first_and_bounded(self) -> None:
        h = Harness(*TREE, process(20, name="a.exe"), process(21, name="b.exe"))
        for pid in (11, 10, 20, 21):
            h.clock.current += timedelta(seconds=1)
            h.terminate.execute(pid, BOOT)

        records = h.list_repairs.execute(limit=3)

        assert [r.target.pid for r in records if r.target] == [21, 20, 10]

    def test_limit_is_capped_and_validated(self) -> None:
        h = Harness(*TREE)

        assert h.list_repairs.execute(limit=100) == ()
        with pytest.raises(ValueError, match="limit"):
            h.list_repairs.execute(limit=0)


def test_list_limits_are_validated() -> None:
    with pytest.raises(ValueError, match="max_limit"):
        RepairListLimits(max_limit=0)


def test_use_cases_share_the_executor() -> None:
    h = Harness(*TREE)

    assert h.terminate.executor is h.executor
    assert h.clear_port.executor is h.executor
