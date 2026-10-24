"""Restart a Windows shell component (Explorer, DWM) for the caller's session. Explicit only.

The recipe: find the session's instance on a fresh snapshot, apply the high-risk gate,
record the intent, revalidate the identity immediately before terminating it (Explorer
through the ordinary controller, DWM only through the elevated helper), then verify by
observation that the old identity is gone *and* a new instance for the session exists and
keeps running. Explorer is started from its fixed system location if Windows has not
recreated it within a grace period; DWM is never started by Windows Medic — if Windows
does not recreate it, the result is a clear partial failure.
"""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from windows_medic.application.ports.component_controller import ComponentController
from windows_medic.application.ports.elevation import ElevatedHelper
from windows_medic.application.ports.process_controller import ProcessController
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.services.repair_audit_trail import RepairAuditTrail
from windows_medic.domain.models.component import StartAttempt, WindowsComponent
from windows_medic.domain.models.elevation import (
    ElevatedOutcome,
    ElevatedRecipe,
    ElevatedRequest,
    ElevatedResult,
)
from windows_medic.domain.models.metric import Metric
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import (
    MemberResult,
    RejectionReason,
    RepairRecord,
    RepairScope,
    RepairStatus,
    RiskLevel,
    TerminationAttempt,
    TerminationOutcome,
    Verification,
)
from windows_medic.domain.policies.component_recovery import (
    ComponentRecipe,
    component_recipe,
    replacement_instance,
    select_component_instance,
    session_of,
)
from windows_medic.domain.policies.repair_execution import member_outcome


@dataclass(frozen=True, slots=True)
class ComponentRepairLimits:
    verify_timeout: timedelta
    verify_interval: timedelta
    auto_restart_wait: timedelta

    def __post_init__(self) -> None:
        if self.verify_timeout < timedelta(0):
            raise ValueError("verify_timeout cannot be negative")
        if self.verify_interval <= timedelta(0):
            raise ValueError("verify_interval must be positive")
        if self.auto_restart_wait < timedelta(0):
            raise ValueError("auto_restart_wait cannot be negative")


@dataclass(frozen=True, slots=True)
class _Plan:
    component: WindowsComponent
    recipe: ComponentRecipe
    old: ProcessIdentity
    name: Metric[str]
    session: int
    since: datetime


@dataclass(frozen=True, slots=True)
class _Observed:
    old_gone: bool
    replacement: ProcessIdentity | None
    start: StartAttempt | None


class RestartWindowsComponent:
    """``windows.explorer.restart`` / ``windows.dwm.restart``."""

    def __init__(
        self,
        *,
        process_reader: ProcessReader,
        controller: ProcessController,
        component_controller: ComponentController,
        elevated_helper: ElevatedHelper,
        trail: RepairAuditTrail,
        own_pid: int,
        high_risk_enabled: bool,
        limits: ComponentRepairLimits,
    ) -> None:
        self._process_reader = process_reader
        self._controller = controller
        self._components = component_controller
        self._elevated = elevated_helper
        self._trail = trail
        self._clock = trail.clock
        self._own_pid = own_pid
        self._high_risk_enabled = high_risk_enabled
        self._limits = limits

    @property
    def limits(self) -> ComponentRepairLimits:
        return self._limits

    @property
    def high_risk_enabled(self) -> bool:
        return self._high_risk_enabled

    def execute(self, component: WindowsComponent) -> RepairRecord:
        """Restart *component* for the caller's session and return the audit record.

        Raises:
            RepairAuditError: If the intended action could not be recorded; nothing mutated.
        """
        # Two concurrent restarts would pick the first one's replacement as "the oldest".
        with self._trail.exclusive:
            return self._execute(component)

    def _execute(self, component: WindowsComponent) -> RepairRecord:
        recipe = component_recipe(component)
        requested_at = self._clock.now()
        record_id = self._trail.new_id()
        snapshot = self._process_reader.snapshot()

        session = session_of(snapshot, self._own_pid)
        if session is None:
            return self._reject(
                recipe, record_id, requested_at, None, RejectionReason.SESSION_UNKNOWN
            )
        instance = select_component_instance(snapshot, component, session=session)
        if instance is None:
            reason = RejectionReason.COMPONENT_NOT_FOUND
            return self._reject(recipe, record_id, requested_at, None, reason)
        if recipe.risk >= RiskLevel.HIGH and not self._high_risk_enabled:
            reason = RejectionReason.HIGH_RISK_DISABLED
            return self._reject(recipe, record_id, requested_at, instance.identity, reason)

        plan = _Plan(component, recipe, instance.identity, instance.name, session, requested_at)
        started = RepairRecord(
            id=record_id,
            action=recipe.action,
            scope=RepairScope.PROCESS,
            status=RepairStatus.STARTED,
            requested_at=requested_at,
            completed_at=None,
            target=plan.old,
            port=None,
            risk=recipe.risk,
            requires_elevation=recipe.requires_elevation,
            rejection=None,
            members=(),
            appeared=(),
            verification=None,
        )
        self._trail.record_intent(started, planned_members=1)

        attempt = self._terminate(plan)
        observed = self._observe(plan, attempt)
        final = self._conclude(started, plan, attempt, observed)
        self._trail.record_outcome(final)
        return final

    # -- steps -----------------------------------------------------------------------------

    def _terminate(self, plan: _Plan) -> TerminationAttempt:
        # Revalidate immediately before acting: the instance may have exited since the plan.
        if self._process_reader.get(plan.old) is None:
            return TerminationAttempt(TerminationOutcome.ALREADY_GONE, "exited before termination")
        if not plan.recipe.requires_elevation:
            return self._controller.terminate(plan.old)
        request = ElevatedRequest(ElevatedRecipe.WINDOWS_DWM_TERMINATE, plan.old, plan.session)
        return _from_elevated(self._elevated.run(request))

    def _observe(self, plan: _Plan, attempt: TerminationAttempt) -> _Observed:
        """Poll until the old identity is gone and a replacement has been seen twice."""
        signalled_at = self._clock.now()
        may_wait = attempt.outcome in (
            TerminationOutcome.SIGNALLED,
            TerminationOutcome.ALREADY_GONE,
            TerminationOutcome.IDENTITY_MISMATCH,
        )
        deadline = signalled_at + (self._limits.verify_timeout if may_wait else timedelta(0))
        start: StartAttempt | None = None
        candidate: ProcessIdentity | None = None
        while True:
            snapshot = self._process_reader.snapshot()
            old_gone = all(o.identity != plan.old for o in snapshot.processes)
            found = (
                replacement_instance(
                    snapshot, plan.component, session=plan.session, old=plan.old, since=plan.since
                )
                if old_gone
                else None
            )
            if found is not None and found.identity == candidate:
                return _Observed(True, found.identity, start)
            candidate = None if found is None else found.identity
            now = self._clock.now()
            if now >= deadline:
                return _Observed(old_gone, None, start)
            if (
                old_gone
                and found is None
                and plan.recipe.may_start
                and start is None
                and now >= signalled_at + self._limits.auto_restart_wait
            ):
                start = self._components.start(plan.component)
            self._clock.sleep(self._limits.verify_interval.total_seconds())

    def _conclude(
        self, started: RepairRecord, plan: _Plan, attempt: TerminationAttempt, observed: _Observed
    ) -> RepairRecord:
        member = MemberResult(
            identity=plan.old,
            name=plan.name,
            depth=0,
            outcome=member_outcome(attempt, gone=observed.old_gone),
            detail=attempt.detail,
        )
        if not observed.old_gone:
            status, passed, detail = RepairStatus.FAILED, False, "old instance still running"
        elif observed.replacement is None:
            seconds = int(self._limits.verify_timeout.total_seconds())
            detail = f"old instance gone; no replacement observed within {seconds} s"
            if observed.start is not None and observed.start.pid is None:
                detail += f" (start attempt: {observed.start.detail})"
            status, passed = RepairStatus.PARTIAL, False
        else:
            origin = (
                "started by Windows Medic"
                if observed.start is not None and observed.start.pid == observed.replacement.pid
                else "recreated by Windows"
            )
            detail = (
                f"old instance gone; replacement {observed.replacement} {origin} and still running"
            )
            status, passed = RepairStatus.SUCCEEDED, True
        checked_at = self._clock.now()
        return replace(
            started,
            status=status,
            completed_at=checked_at,
            members=(member,),
            replacement=observed.replacement,
            verification=Verification(passed, detail, checked_at),
        )

    def _reject(
        self,
        recipe: ComponentRecipe,
        record_id: str,
        requested_at: datetime,
        target: ProcessIdentity | None,
        reason: RejectionReason,
    ) -> RepairRecord:
        return self._trail.reject(
            action=recipe.action,
            scope=RepairScope.PROCESS,
            target=target,
            reason=reason,
            risk=recipe.risk,
            requires_elevation=recipe.requires_elevation,
            record_id=record_id,
            requested_at=requested_at,
        )


def _from_elevated(result: ElevatedResult) -> TerminationAttempt:
    if result.outcome is ElevatedOutcome.COMPLETED and result.termination is not None:
        return result.termination
    if result.outcome is ElevatedOutcome.DECLINED:
        return TerminationAttempt(TerminationOutcome.ERROR, f"elevation declined: {result.detail}")
    if result.outcome is ElevatedOutcome.REJECTED:
        reason = None if result.rejection is None else result.rejection.value
        return TerminationAttempt(
            TerminationOutcome.ERROR, f"elevated helper rejected the request: {reason}"
        )
    if result.outcome is ElevatedOutcome.TIMED_OUT:
        return TerminationAttempt(TerminationOutcome.ERROR, "elevated helper timed out")
    return TerminationAttempt(TerminationOutcome.ERROR, f"elevated helper failed: {result.detail}")
