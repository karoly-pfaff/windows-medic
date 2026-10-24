"""InspectProcess: identity-validated lookup with bounded tree context, protection and risk."""

from datetime import datetime, timedelta

import pytest

from tests.builders import BOOT, T0, identity, process, process_snapshot
from tests.fakes import FakeProcessReader
from windows_medic.application.use_cases.inspect_process import (
    InspectionLimits,
    InspectProcess,
    ProcessInspection,
)
from windows_medic.domain.errors import ProcessNotFoundError, StaleIdentityError
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.tree import (
    AncestryEnd,
    UnresolvedParent,
    UnresolvedParentReason,
)
from windows_medic.domain.policies.protection import ProtectionLevel, ProtectionPolicy
from windows_medic.domain.policies.risk_markers import AncestryPolicy, RiskMarker

PROTECTION = ProtectionPolicy(
    own_pid=4242,
    windows_medic_markers=("windows-medic",),
    user_protected_names=(),
    windows_directory="C:\\Windows",
)
ANCESTRY = AncestryPolicy(claude_markers=("claude",), terminal_process_names=("cmd.exe",))
LIMITS = InspectionLimits(max_ancestors=3, max_descendants=2)


def at(seconds: int) -> datetime:
    return BOOT + timedelta(seconds=seconds)


TERMINAL = process(1, created=BOOT, name="cmd.exe")
CLAUDE = process(2, created=at(1), parent_pid=1, name="claude.exe")
SHELL = process(3, created=at(2), parent_pid=2, name="pwsh.exe")
TARGET = process(4, created=at(3), parent_pid=3, name="node.exe")
CHILD_A = process(5, created=at(4), parent_pid=4, name="esbuild.exe")
CHILD_B = process(6, created=at(4), parent_pid=4, name="node.exe")
GRANDCHILD = process(7, created=at(5), parent_pid=5, name="lsass.exe")
ALL = (TERMINAL, CLAUDE, SHELL, TARGET, CHILD_A, CHILD_B, GRANDCHILD)


def inspect(
    pid: int, create_time: datetime | None = None, *observations: ProcessObservation
) -> ProcessInspection:
    reader = FakeProcessReader(process_snapshot(*(observations or ALL), observed_at=T0))
    use_case = InspectProcess(
        process_reader=reader, protection=PROTECTION, ancestry=ANCESTRY, limits=LIMITS
    )
    return use_case.execute(pid, create_time)


class TestLookup:
    def test_pid_alone_resolves_the_current_process_with_that_pid(self) -> None:
        inspection = inspect(4)

        assert inspection.observation is TARGET
        assert inspection.observed_at == T0

    def test_matching_create_time_is_accepted(self) -> None:
        assert inspect(4, TARGET.identity.create_time).observation is TARGET

    def test_mismatching_create_time_is_a_stale_identity(self) -> None:
        stale = identity(4, BOOT - timedelta(days=1))

        with pytest.raises(StaleIdentityError) as excinfo:
            inspect(4, stale.create_time)

        assert excinfo.value.requested == stale
        assert excinfo.value.current == TARGET.identity
        assert "pid 4" in str(excinfo.value)

    def test_unknown_pid_is_not_found(self) -> None:
        with pytest.raises(ProcessNotFoundError, match="pid 999"):
            inspect(999)

    def test_negative_pid_is_rejected_before_any_observation(self) -> None:
        with pytest.raises(ValueError, match="pid"):
            inspect(-1)


class TestTreeContext:
    def test_parent_and_ancestors_nearest_first_with_protection(self) -> None:
        inspection = inspect(4)

        assert inspection.parent == SHELL.identity
        assert [a.identity.pid for a in inspection.ancestors] == [3, 2, 1]
        assert [a.depth for a in inspection.ancestors] == [1, 2, 3]
        assert inspection.ancestors[0].name == "pwsh.exe"
        assert inspection.ancestors[0].protection is ProtectionLevel.NONE
        assert inspection.ancestry_end is AncestryEnd.UNRESOLVED

    def test_ancestors_are_bounded_and_truncation_is_reported(self) -> None:
        inspection = inspect(7)

        assert [a.identity.pid for a in inspection.ancestors] == [5, 4, 3]
        assert inspection.ancestors_truncated is True
        assert inspect(4).ancestors_truncated is False

    def test_descendants_are_bounded_breadth_first_and_truncation_is_reported(self) -> None:
        inspection = inspect(4)

        assert [(d.identity.pid, d.depth) for d in inspection.descendants] == [(5, 1), (6, 1)]
        assert inspection.descendants_truncated is True
        assert inspection.descendants[0].name == "esbuild.exe"

    def test_leaf_process_has_no_descendants(self) -> None:
        inspection = inspect(6)

        assert inspection.descendants == ()
        assert inspection.descendants_truncated is False

    def test_unresolved_parent_is_reported_as_evidence(self) -> None:
        orphan = process(50, created=at(9), parent_pid=999)

        inspection = inspect(50, None, orphan)

        assert inspection.parent == UnresolvedParent(999, UnresolvedParentReason.PARENT_GONE)
        assert inspection.ancestors == ()


class TestPolicyOutputs:
    def test_protection_verdict_and_risk_markers_are_included(self) -> None:
        inspection = inspect(4)

        assert inspection.protection.level is ProtectionLevel.NONE
        assert inspection.risk_markers == (
            RiskMarker.CLAUDE_ANCESTRY,
            RiskMarker.TERMINAL_ANCESTRY,
            RiskMarker.PROTECTED_DESCENDANT,
        )

    def test_critical_target_is_reported_as_critical(self) -> None:
        inspection = inspect(7)

        assert inspection.protection.level is ProtectionLevel.CRITICAL
        assert inspection.descendants_truncated is False

    def test_protected_descendant_beyond_the_display_limit_is_still_marked(self) -> None:
        root = process(100, created=BOOT)
        kids = [process(pid, created=at(1), parent_pid=100) for pid in range(101, 110)]
        hidden = process(200, created=at(2), parent_pid=109, name="lsass.exe")

        inspection = inspect(100, None, root, *kids, hidden)

        assert len(inspection.descendants) == LIMITS.max_descendants
        assert RiskMarker.PROTECTED_DESCENDANT in inspection.risk_markers

    def test_descendant_protection_uses_the_same_policy(self) -> None:
        inspection = inspect(5)

        [grandchild] = inspection.descendants
        assert grandchild.protection is ProtectionLevel.CRITICAL


class TestLimitsValidation:
    def test_limits_must_be_non_negative(self) -> None:
        with pytest.raises(ValueError, match="max_ancestors"):
            InspectionLimits(max_ancestors=-1, max_descendants=1)
        with pytest.raises(ValueError, match="max_descendants"):
            InspectionLimits(max_ancestors=1, max_descendants=-1)
