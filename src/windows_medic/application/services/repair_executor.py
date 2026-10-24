"""Execute a termination repair with strong identity and protection checks.

The order of operations is the safety model:

1. take a fresh snapshot and revalidate every target by exact identity — a missing PID or
   a different create time is a rejection, never a silent re-target;
2. classify protection and risk on that snapshot and reject blocked targets before any
   OS call;
3. build the member list from the fresh tree (target first, then descendants by depth),
   bounded;
4. record the intended action in the audit — no audit, no mutation;
5. ask the controller to terminate each member by exact identity;
6. verify the postcondition by observation (bounded polling), report survivors and
   members that appeared after the plan, run the caller's extra postcondition;
7. record the outcome.
"""

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from windows_medic.application.ports.process_controller import ProcessController
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.services.repair_audit_trail import RepairAuditTrail
from windows_medic.domain.errors import ObservationError
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.repair import (
    MemberOutcome,
    MemberResult,
    PlannedMember,
    RejectionReason,
    RepairAction,
    RepairRecord,
    RepairScope,
    RepairStatus,
    RiskLevel,
    TerminationAttempt,
    Verification,
)
from windows_medic.domain.models.samples import ProcessSnapshot
from windows_medic.domain.models.tree import ProcessTree, build_process_tree
from windows_medic.domain.policies.protection import ProtectionPolicy, classify_protection
from windows_medic.domain.policies.repair_execution import (
    appeared_since,
    member_outcome,
    rejection_for,
    repair_status,
    termination_order,
)
from windows_medic.domain.policies.repair_risk import assess_repair_risk
from windows_medic.domain.policies.risk_markers import AncestryPolicy, assess_risk_markers


@dataclass(frozen=True, slots=True)
class RepairLimits:
    verify_timeout: timedelta
    verify_interval: timedelta
    max_tree_members: int

    def __post_init__(self) -> None:
        if self.verify_timeout < timedelta(0):
            raise ValueError("verify_timeout cannot be negative")
        if self.verify_interval <= timedelta(0):
            raise ValueError("verify_interval must be positive")
        if self.max_tree_members < 1:
            raise ValueError("max_tree_members must be at least 1")


@dataclass(frozen=True, slots=True)
class RepairRequest:
    """What to do: a recipe, a scope and the exact identities to act on."""

    action: RepairAction
    scope: RepairScope
    targets: tuple[ProcessIdentity, ...]
    port: int | None = None

    def __post_init__(self) -> None:
        if not self.targets:
            raise ValueError("a repair request needs at least one target")


@dataclass(frozen=True, slots=True)
class _Plan:
    members: tuple[PlannedMember, ...]
    observations: dict[ProcessIdentity, ProcessObservation]
    risk: RiskLevel
    requires_elevation: bool


@dataclass(frozen=True, slots=True)
class _Rejection:
    reason: RejectionReason
    risk: RiskLevel | None = None
    requires_elevation: bool = False


class RepairExecutor:
    """Runs termination repairs for the use cases; owns the audit trail."""

    def __init__(
        self,
        *,
        process_reader: ProcessReader,
        controller: ProcessController,
        trail: RepairAuditTrail,
        protection: ProtectionPolicy,
        ancestry: AncestryPolicy,
        limits: RepairLimits,
    ) -> None:
        self._process_reader = process_reader
        self._controller = controller
        self._trail = trail
        self._clock = trail.clock
        self._protection = protection
        self._ancestry = ancestry
        self._limits = limits

    @property
    def limits(self) -> RepairLimits:
        return self._limits

    @property
    def trail(self) -> RepairAuditTrail:
        return self._trail

    def execute(
        self, request: RepairRequest, *, postcondition: Callable[[], Verification] | None = None
    ) -> RepairRecord:
        """Run *request* and return its audit record (also persisted).

        Raises:
            RepairAuditError: If the intended action cannot be recorded; nothing is mutated.
        """
        with self._trail.exclusive:
            return self._execute(request, postcondition)

    def _execute(
        self, request: RepairRequest, postcondition: Callable[[], Verification] | None
    ) -> RepairRecord:
        requested_at = self._clock.now()
        record_id = self._trail.new_id()
        snapshot = self._process_reader.snapshot()
        tree = build_process_tree(snapshot)
        planned = self._plan(request, snapshot, tree)

        if isinstance(planned, _Rejection):
            return self._trail.reject(
                action=request.action,
                scope=request.scope,
                target=request.targets[0],
                port=request.port,
                reason=planned.reason,
                risk=planned.risk,
                requires_elevation=planned.requires_elevation,
                record_id=record_id,
                requested_at=requested_at,
            )

        started = RepairRecord(
            id=record_id,
            action=request.action,
            scope=request.scope,
            status=RepairStatus.STARTED,
            requested_at=requested_at,
            completed_at=None,
            target=request.targets[0],
            port=request.port,
            risk=planned.risk,
            requires_elevation=planned.requires_elevation,
            rejection=None,
            members=(),
            appeared=(),
            verification=None,
        )
        self._trail.record_intent(started, planned_members=len(planned.members))

        attempts = {m.identity: self._controller.terminate(m.identity) for m in planned.members}
        try:
            final = self._verify(started, planned, attempts, snapshot.observed_at, postcondition)
        except ObservationError as exc:
            # The mutation happened; its outcome is recorded even when it cannot be observed.
            final = self._unverified(started, planned, attempts, exc)
        self._trail.record_outcome(final)
        return final

    # -- planning --------------------------------------------------------------------------

    def _plan(
        self, request: RepairRequest, snapshot: ProcessSnapshot, tree: ProcessTree
    ) -> _Plan | _Rejection:
        members: list[PlannedMember] = []
        observations: dict[ProcessIdentity, ProcessObservation] = {}
        risks: list[RiskLevel] = []
        requires_elevation = False
        for target in request.targets:
            if not tree.contains(target):
                reason = (
                    RejectionReason.STALE_IDENTITY
                    if any(o.identity.pid == target.pid for o in snapshot.processes)
                    else RejectionReason.TARGET_NOT_FOUND
                )
                return _Rejection(reason)
            observation = tree.observation(target)
            verdict = classify_protection(observation, self._protection)
            markers = assess_risk_markers(
                target,
                tree,
                protection=self._protection,
                ancestry=self._ancestry,
                descendant_limit=self._limits.max_tree_members + 1,
            )
            risk = assess_repair_risk(
                observation, protection=verdict, risk_markers=markers, scope=request.scope
            )
            if risk.blockers:
                return _Rejection(rejection_for(risk.blockers), risk.level, risk.requires_elevation)
            risks.append(risk.level)
            requires_elevation = requires_elevation or risk.requires_elevation

            descendants = (
                tree.descendants_of(target, limit=self._limits.max_tree_members + 1)
                if request.scope is RepairScope.TREE
                else ()
            )
            if len(descendants) + 1 > self._limits.max_tree_members:
                return _Rejection(RejectionReason.TREE_TOO_LARGE, risk.level, requires_elevation)
            for member in termination_order(target, descendants):
                if member.identity not in observations:
                    members.append(member)
                    observations[member.identity] = tree.observation(member.identity)
        return _Plan(tuple(members), observations, max(risks), requires_elevation)

    # -- verification ----------------------------------------------------------------------

    def _unverified(
        self,
        started: RepairRecord,
        plan: _Plan,
        attempts: dict[ProcessIdentity, TerminationAttempt],
        error: ObservationError,
    ) -> RepairRecord:
        members = tuple(
            MemberResult(
                identity=m.identity,
                name=plan.observations[m.identity].name,
                depth=m.depth,
                outcome=MemberOutcome.UNVERIFIED,
                detail=attempts[m.identity].detail,
            )
            for m in plan.members
        )
        checked_at = self._clock.now()
        return replace(
            started,
            status=RepairStatus.FAILED,
            completed_at=checked_at,
            members=members,
            verification=Verification(False, f"could not verify: {error}", checked_at),
        )

    def _verify(
        self,
        started: RepairRecord,
        plan: _Plan,
        attempts: dict[ProcessIdentity, TerminationAttempt],
        planned_at: datetime,
        postcondition: Callable[[], Verification] | None,
    ) -> RepairRecord:
        planned = set(plan.observations)
        deadline = self._clock.now() + self._limits.verify_timeout
        while True:
            after = self._process_reader.snapshot()
            alive = {o.identity for o in after.processes} & planned
            if not alive or self._clock.now() >= deadline:
                break
            self._clock.sleep(self._limits.verify_interval.total_seconds())

        members = tuple(
            MemberResult(
                identity=m.identity,
                name=plan.observations[m.identity].name,
                depth=m.depth,
                outcome=member_outcome(attempts[m.identity], gone=m.identity not in alive),
                detail=attempts[m.identity].detail,
            )
            for m in plan.members
        )
        appeared = appeared_since(planned, after, since=planned_at)
        status = repair_status(members)
        gone = sum(1 for m in members if m.outcome.gone)
        details = [f"{gone} of {len(members)} members gone"]
        passed = gone == len(members)
        if alive:
            details.append("still running: " + ", ".join(f"pid {i.pid}" for i in sorted(alive)))
        if appeared and started.scope is RepairScope.TREE:
            passed = False
            details.append(
                "appeared after the plan and not targeted: "
                + ", ".join(f"pid {i.pid}" for i in appeared)
            )
        if postcondition is not None:
            extra = postcondition()
            passed = passed and extra.passed
            details.append(extra.detail)
        if not passed and status is RepairStatus.SUCCEEDED:
            status = RepairStatus.PARTIAL
        checked_at = self._clock.now()
        return replace(
            started,
            status=status,
            completed_at=checked_at,
            members=members,
            appeared=appeared,
            verification=Verification(passed, "; ".join(details), checked_at),
        )
