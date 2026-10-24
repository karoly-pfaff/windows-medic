"""InspectPort: exact owner identity, races made explicit, eligibility never implied."""

from datetime import timedelta

import pytest

from tests.builders import BOOT, T0, listener, process, process_snapshot
from tests.fakes import FakeNetworkReader, FakeProcessReader
from windows_medic.application.use_cases.inspect_port import (
    InspectPort,
    PortInspection,
    UnresolvedOwnerReason,
)
from windows_medic.application.use_cases.inspect_process import InspectionLimits
from windows_medic.domain.models.network import AddressFamily, ListeningEndpoint
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.samples import ProcessSnapshot
from windows_medic.domain.policies.port_clearing import ClearPortBlocker
from windows_medic.domain.policies.protection import ProtectionLevel, ProtectionPolicy
from windows_medic.domain.policies.risk_markers import AncestryPolicy, RiskMarker

PROTECTION = ProtectionPolicy(
    own_pid=4242,
    windows_medic_markers=("windows-medic",),
    user_protected_names=(),
    windows_directory="C:\\Windows",
)
ANCESTRY = AncestryPolicy(claude_markers=("claude",), terminal_process_names=("pwsh.exe",))
LIMITS = InspectionLimits(max_ancestors=4, max_descendants=4, max_port_owners=3)

SHELL = process(1, created=BOOT, name="pwsh.exe")
NODE = process(100, created=BOOT + timedelta(seconds=1), parent_pid=1, name="node.exe")
SVCHOST = process(200, created=BOOT + timedelta(seconds=2), parent_pid=1, name="svchost.exe")
BASELINE = process_snapshot(SHELL, NODE, SVCHOST, observed_at=T0)


def inspect(
    port: int,
    *listeners: ListeningEndpoint,
    baseline: ProcessSnapshot = BASELINE,
    lookup: ProcessSnapshot | None = None,
    limits: InspectionLimits = LIMITS,
) -> tuple[PortInspection, FakeProcessReader, FakeNetworkReader]:
    processes = FakeProcessReader(baseline, lookup=lookup)
    network = FakeNetworkReader(*listeners)
    use_case = InspectPort(
        process_reader=processes,
        network_reader=network,
        protection=PROTECTION,
        ancestry=ANCESTRY,
        limits=limits,
    )
    return use_case.execute(port), processes, network


class TestValidation:
    @pytest.mark.parametrize("port", [0, -1, 65536])
    def test_port_out_of_range_is_rejected_before_any_observation(self, port: int) -> None:
        with pytest.raises(ValueError, match="port"):
            inspect(port)


class TestClosedPort:
    def test_reports_no_owners_and_no_eligibility(self) -> None:
        inspection, _, _ = inspect(5173, listener(8080, 100))

        assert inspection.port == 5173
        assert inspection.observed_at == T0
        assert inspection.owners == ()
        assert inspection.unresolved == ()
        assert inspection.truncated is False
        assert inspection.clear_port.eligible is False
        assert inspection.clear_port.blockers == (ClearPortBlocker.NO_OWNER,)


class TestResolvedOwner:
    def test_owner_is_the_exact_baseline_identity_confirmed_afterwards(self) -> None:
        inspection, processes, network = inspect(5173, listener(5173, 100))

        [owner] = inspection.owners
        assert owner.identity == NODE.identity
        assert owner.name == "node.exe"
        assert owner.exe_path == "C:\\bin\\node.exe"
        assert owner.command_line == ("node.exe",)
        assert owner.endpoints == (listener(5173, 100),)
        assert processes.calls == 1
        assert processes.lookups == [NODE.identity]
        assert network.calls == 1

    def test_owner_carries_tree_protection_and_risk_context(self) -> None:
        inspection, _, _ = inspect(5173, listener(5173, 100))

        [owner] = inspection.owners
        assert owner.parent == SHELL.identity
        assert [a.identity.pid for a in owner.ancestors] == [1]
        assert owner.protection.level is ProtectionLevel.NONE
        assert owner.risk_markers == (RiskMarker.TERMINAL_ANCESTRY,)

    def test_unprotected_owner_makes_the_port_eligible(self) -> None:
        inspection, _, _ = inspect(5173, listener(5173, 100))

        assert inspection.clear_port.eligible is True
        assert inspection.clear_port.blockers == ()

    def test_dual_stack_listeners_of_one_process_are_one_owner(self) -> None:
        inspection, _, _ = inspect(
            5173, listener(5173, 100), listener(5173, 100, family=AddressFamily.IPV6)
        )

        [owner] = inspection.owners
        assert {e.family for e in owner.endpoints} == {AddressFamily.IPV4, AddressFamily.IPV6}

    def test_owners_are_ordered_by_identity(self) -> None:
        inspection, _, _ = inspect(5173, listener(5173, 200), listener(5173, 100))

        assert [o.identity.pid for o in inspection.owners] == [100, 200]


class TestProtectedOwner:
    def test_windows_component_owner_is_marked_and_blocks_clearing(self) -> None:
        inspection, _, _ = inspect(135, listener(135, 200))

        [owner] = inspection.owners
        assert owner.protection.level is ProtectionLevel.WINDOWS_COMPONENT
        assert inspection.clear_port.eligible is False
        assert inspection.clear_port.blockers == (ClearPortBlocker.OWNER_PROTECTED,)


class TestRaces:
    def test_owner_exiting_after_baseline_is_a_race_not_an_owner(self) -> None:
        after = process_snapshot(SHELL, SVCHOST, observed_at=T0)

        inspection, _, _ = inspect(5173, listener(5173, 100), lookup=after)

        assert inspection.owners == ()
        [unresolved] = inspection.unresolved
        assert unresolved.reported_pid == 100
        assert unresolved.reason is UnresolvedOwnerReason.OWNER_CHANGED
        assert inspection.clear_port.blockers == (ClearPortBlocker.OWNER_UNRESOLVED,)

    def test_reused_pid_never_becomes_the_owner(self) -> None:
        impostor = process(100, created=T0 + timedelta(seconds=5), name="evil.exe")
        after = process_snapshot(SHELL, impostor, SVCHOST, observed_at=T0)

        inspection, processes, _ = inspect(5173, listener(5173, 100), lookup=after)

        assert inspection.owners == ()
        assert inspection.unresolved[0].reason is UnresolvedOwnerReason.OWNER_CHANGED
        assert processes.lookups == [NODE.identity]

    def test_pid_missing_from_baseline_is_unverified(self) -> None:
        inspection, processes, _ = inspect(5173, listener(5173, 999))

        [unresolved] = inspection.unresolved
        assert unresolved.reason is UnresolvedOwnerReason.OWNER_UNVERIFIED
        assert processes.lookups == []

    def test_os_reporting_no_pid_is_unknown(self) -> None:
        inspection, _, _ = inspect(5173, listener(5173, None))

        [unresolved] = inspection.unresolved
        assert unresolved.reported_pid is None
        assert unresolved.reason is UnresolvedOwnerReason.OWNER_UNKNOWN

    def test_resolved_and_unresolved_owners_coexist(self) -> None:
        inspection, _, _ = inspect(5173, listener(5173, 100), listener(5173, 999))

        assert [o.identity.pid for o in inspection.owners] == [100]
        assert [u.reported_pid for u in inspection.unresolved] == [999]
        assert inspection.clear_port.eligible is False


class TestBounds:
    def test_owner_list_is_bounded_and_truncation_blocks_clearing(self) -> None:
        crowd = [
            process(pid, created=BOOT + timedelta(seconds=pid), name="node.exe")
            for pid in range(300, 310)
        ]
        baseline = process_snapshot(*crowd, observed_at=T0)
        listeners = [listener(5173, pid) for pid in range(300, 310)]

        inspection, _, _ = inspect(5173, *listeners, baseline=baseline)

        assert len(inspection.owners) == 3
        assert inspection.truncated is True
        assert inspection.clear_port.eligible is False
        assert ClearPortBlocker.OWNER_UNRESOLVED in inspection.clear_port.blockers

    def test_limits_require_at_least_one_owner_slot(self) -> None:
        with pytest.raises(ValueError, match="max_port_owners"):
            InspectionLimits(max_ancestors=1, max_descendants=1, max_port_owners=0)


def test_owner_observation_is_the_baseline_one() -> None:
    inspection, _, _ = inspect(5173, listener(5173, 100))

    assert isinstance(inspection.owners[0].observation, ProcessObservation)
    assert inspection.owners[0].observation is NODE
