"""RestartWindowsComponent: Explorer and DWM recovery over fakes, never touching the real shell."""

from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from tests.builders import BOOT, T0, identity, process
from tests.fakes import (
    FakeClock,
    FakeComponentController,
    FakeElevatedHelper,
    FakeProcessWorld,
    FakeRepairAudit,
)
from windows_medic.application.services.repair_audit_trail import RepairAuditTrail
from windows_medic.application.use_cases.restart_windows_component import (
    ComponentRepairLimits,
    RestartWindowsComponent,
)
from windows_medic.domain.errors import RepairAuditError
from windows_medic.domain.models.component import WindowsComponent
from windows_medic.domain.models.elevation import (
    ElevatedOutcome,
    ElevatedRecipe,
    ElevatedRejection,
    ElevatedResult,
)
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.repair import (
    MemberOutcome,
    RejectionReason,
    RepairAction,
    RepairScope,
    RepairStatus,
    RiskLevel,
    TerminationAttempt,
)

OWN_PID = 4242
LIMITS = ComponentRepairLimits(
    verify_timeout=timedelta(seconds=10),
    verify_interval=timedelta(milliseconds=500),
    auto_restart_wait=timedelta(seconds=2),
)


def in_session(
    pid: int, name: str, session: int = 1, *, created: datetime = BOOT
) -> ProcessObservation:
    return replace(process(pid, name=name, created=created), session_id=session)


def explorer(pid: int = 100, *, created: datetime = BOOT, session: int = 1) -> ProcessObservation:
    return in_session(pid, "explorer.exe", session, created=created)


class Harness:
    def __init__(
        self,
        *processes: ProcessObservation,
        high_risk: bool = False,
        replacement: ProcessObservation | None = None,
        elevated: ElevatedResult | None = None,
    ) -> None:
        self.clock = FakeClock(T0)
        self.world = FakeProcessWorld(
            self.clock, in_session(OWN_PID, "windows-medic.exe"), *processes
        )
        self.audit = FakeRepairAudit()
        self.components = FakeComponentController(self.world, replacement=replacement)
        self.elevated = FakeElevatedHelper(self.world, scripted=elevated)
        ids = iter(f"rep-{n}" for n in range(1, 100))
        self.trail = RepairAuditTrail(
            audit=self.audit, clock=self.clock, retention=timedelta(days=30), ids=lambda: next(ids)
        )
        self.use_case = RestartWindowsComponent(
            process_reader=self.world,
            controller=self.world,
            component_controller=self.components,
            elevated_helper=self.elevated,
            trail=self.trail,
            own_pid=OWN_PID,
            high_risk_enabled=high_risk,
            limits=LIMITS,
        )


class TestExplorer:
    def test_windows_recreates_explorer_and_the_replacement_is_verified(self) -> None:
        h = Harness(explorer(100), explorer(101, created=BOOT + timedelta(minutes=5)))
        recreated = explorer(150, created=T0)
        h.world.spawns[identity(100)] = recreated  # Windows restarts the shell by itself

        record = h.use_case.execute(WindowsComponent.EXPLORER)

        assert record.status is RepairStatus.SUCCEEDED
        assert record.action is RepairAction.WINDOWS_EXPLORER_RESTART
        assert record.scope is RepairScope.PROCESS
        assert record.target == identity(100)  # the oldest instance: the shell
        assert record.risk is RiskLevel.MEDIUM
        assert record.requires_elevation is False
        assert [(m.identity, m.outcome) for m in record.members] == [
            (identity(100), MemberOutcome.TERMINATED)
        ]
        assert record.replacement == recreated.identity
        assert record.verification is not None
        assert record.verification.passed is True
        assert record.verification.detail == (
            "old instance gone; replacement pid 150 @ 2026-09-11T12:00:00+00:00 "
            "recreated by Windows and still running"
        )
        assert h.components.started == []
        assert h.elevated.requests == []
        folder_window = identity(101, BOOT + timedelta(minutes=5))
        assert folder_window in h.world.live  # the separate-process folder window survives
        assert [r.status for r in h.audit.saves] == [RepairStatus.STARTED, RepairStatus.SUCCEEDED]

    def test_the_restart_runs_under_the_trails_exclusive_lock(self) -> None:
        h = Harness(explorer(100))
        h.world.spawns[identity(100)] = explorer(150, created=T0)
        trail = h.trail
        held: list[bool] = []
        original = h.world.terminate

        def observing(identity: ProcessIdentity) -> TerminationAttempt:
            held.append(trail.exclusive.locked())
            return original(identity)

        h.world.terminate = observing  # type: ignore[method-assign]

        h.use_case.execute(WindowsComponent.EXPLORER)

        assert held == [True]
        assert not trail.exclusive.locked()

    def test_explorer_is_started_when_windows_does_not_recreate_it(self) -> None:
        started = explorer(160, created=T0 + timedelta(seconds=2))
        h = Harness(explorer(100), replacement=started)

        record = h.use_case.execute(WindowsComponent.EXPLORER)

        assert record.status is RepairStatus.SUCCEEDED
        assert h.components.started == [WindowsComponent.EXPLORER]
        assert record.replacement == started.identity
        assert record.verification is not None
        assert "started by Windows Medic and still running" in record.verification.detail
        # Windows got its auto-restart window (2 s at 0.5 s polls) before we stepped in.
        assert h.clock.sleeps[:4] == [0.5, 0.5, 0.5, 0.5]

    def test_no_replacement_within_the_timeout_is_a_partial_failure(self) -> None:
        h = Harness(explorer(100))

        record = h.use_case.execute(WindowsComponent.EXPLORER)

        assert record.status is RepairStatus.PARTIAL
        assert record.members[0].outcome is MemberOutcome.TERMINATED
        assert record.replacement is None
        assert record.verification is not None
        assert record.verification.passed is False
        assert record.verification.detail == (
            "old instance gone; no replacement observed within 10 s "
            "(start attempt: start failed: file not found)"
        )
        assert h.clock.now() >= T0 + timedelta(seconds=10)

    def test_a_replacement_that_dies_again_is_not_healthy(self) -> None:
        h = Harness(explorer(100))
        flaky = explorer(150, created=T0)
        h.world.spawns[identity(100)] = flaky
        h.world.dies_after(flaky.identity, snapshots=3)  # seen once, gone at the health re-check

        record = h.use_case.execute(WindowsComponent.EXPLORER)

        assert record.status is RepairStatus.PARTIAL
        assert record.replacement is None
        assert record.verification is not None
        assert record.verification.detail.startswith("old instance gone; no replacement observed")

    def test_a_shell_that_refuses_to_die_fails(self) -> None:
        h = Harness(explorer(100))
        h.world.denied.add(identity(100))

        record = h.use_case.execute(WindowsComponent.EXPLORER)

        assert record.status is RepairStatus.FAILED
        assert record.members[0].outcome is MemberOutcome.ACCESS_DENIED
        assert record.verification is not None
        assert record.verification.detail == "old instance still running"
        assert h.components.started == []

    def test_the_identity_is_revalidated_immediately_before_termination(self) -> None:
        h = Harness(explorer(100))
        h.world.vanish_after_plan.add(identity(100))
        h.world.live[identity(150, T0)] = explorer(150, created=T0)

        record = h.use_case.execute(WindowsComponent.EXPLORER)

        assert record.members[0].outcome is MemberOutcome.ALREADY_GONE
        assert h.world.terminations == []
        assert record.status is RepairStatus.SUCCEEDED


class TestRejections:
    def test_missing_component_in_our_session_is_rejected(self) -> None:
        h = Harness(explorer(200, session=2))

        record = h.use_case.execute(WindowsComponent.EXPLORER)

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.COMPONENT_NOT_FOUND
        assert record.target is None
        assert h.world.terminations == []

    def test_unknown_own_session_is_rejected(self) -> None:
        h = Harness(explorer(100))
        h.world.live[identity(OWN_PID)] = replace(
            h.world.live[identity(OWN_PID)], session_id=Unavailable(UnavailableReason.ACCESS_DENIED)
        )

        record = h.use_case.execute(WindowsComponent.EXPLORER)

        assert record.rejection is RejectionReason.SESSION_UNKNOWN

    def test_dwm_is_high_risk_and_disabled_by_default(self) -> None:
        h = Harness(in_session(300, "dwm.exe"))

        record = h.use_case.execute(WindowsComponent.DWM)

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.HIGH_RISK_DISABLED
        assert record.risk is RiskLevel.HIGH
        assert record.requires_elevation is True
        assert record.target == identity(300)
        assert h.elevated.requests == []
        assert h.world.terminations == []

    def test_audit_failure_prevents_any_mutation(self) -> None:
        h = Harness(explorer(100))
        h.audit.fail_saves.add(1)

        with pytest.raises(RepairAuditError):
            h.use_case.execute(WindowsComponent.EXPLORER)

        assert h.world.terminations == []


class TestDwm:
    def test_dwm_is_terminated_through_the_elevated_helper_and_recreation_verified(
        self,
    ) -> None:
        h = Harness(in_session(300, "dwm.exe"), high_risk=True)
        h.world.spawns[identity(300)] = in_session(350, "dwm.exe", created=T0)

        record = h.use_case.execute(WindowsComponent.DWM)

        assert record.status is RepairStatus.SUCCEEDED
        assert record.action is RepairAction.WINDOWS_DWM_RESTART
        assert record.risk is RiskLevel.HIGH
        assert record.requires_elevation is True
        assert [r.recipe for r in h.elevated.requests] == [ElevatedRecipe.WINDOWS_DWM_TERMINATE]
        assert h.elevated.requests[0].target == identity(300)
        assert h.elevated.requests[0].session == 1
        assert h.world.terminations == [identity(300)]
        assert h.components.started == []
        assert record.replacement == identity(350, T0)

    def test_dwm_is_never_started_by_us_when_windows_does_not_recreate_it(self) -> None:
        h = Harness(
            in_session(300, "dwm.exe"), high_risk=True, replacement=in_session(9, "dwm.exe")
        )

        record = h.use_case.execute(WindowsComponent.DWM)

        assert record.status is RepairStatus.PARTIAL
        assert h.components.started == []
        assert record.verification is not None
        assert (
            record.verification.detail == "old instance gone; no replacement observed within 10 s"
        )

    @pytest.mark.parametrize(
        ("result", "detail"),
        [
            (
                ElevatedResult(ElevatedOutcome.DECLINED, detail="the UAC prompt was cancelled"),
                "elevation declined: the UAC prompt was cancelled",
            ),
            (
                ElevatedResult(
                    ElevatedOutcome.REJECTED, rejection=ElevatedRejection.NOT_THE_COMPONENT
                ),
                "elevated helper rejected the request: not_the_component",
            ),
            (ElevatedResult(ElevatedOutcome.TIMED_OUT), "elevated helper timed out"),
            (
                ElevatedResult(ElevatedOutcome.FAILED, detail="helper exited with code 1"),
                "elevated helper failed: helper exited with code 1",
            ),
        ],
    )
    def test_elevation_problems_fail_with_a_clear_record(
        self, result: ElevatedResult, detail: str
    ) -> None:
        h = Harness(in_session(300, "dwm.exe"), high_risk=True, elevated=result)

        record = h.use_case.execute(WindowsComponent.DWM)

        assert record.status is RepairStatus.FAILED
        assert record.members[0].outcome is MemberOutcome.ERROR
        assert record.members[0].detail == detail
        assert h.world.terminations == []
        assert h.audit.records["rep-1"].status is RepairStatus.FAILED


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"verify_timeout": timedelta(seconds=-1)}, "verify_timeout"),
        ({"verify_interval": timedelta(0)}, "verify_interval"),
        ({"auto_restart_wait": timedelta(seconds=-1)}, "auto_restart_wait"),
    ],
)
def test_limits_are_validated(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        replace(LIMITS, **overrides)  # type: ignore[arg-type]
