"""Pure rules of repair execution: ordering, rejection, outcomes, status and drift.

The application service does the I/O; everything that decides something lives here so it
is exhaustively testable without a process to kill.
"""

from collections.abc import Sequence, Set
from datetime import datetime

from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import (
    MemberOutcome,
    MemberResult,
    PlannedMember,
    RejectionReason,
    RepairBlocker,
    RepairStatus,
    TerminationAttempt,
    TerminationOutcome,
)
from windows_medic.domain.models.samples import ProcessSnapshot
from windows_medic.domain.models.tree import Descendant

_REJECTION_FOR_BLOCKER = {
    RepairBlocker.TARGET_PROTECTED: RejectionReason.TARGET_PROTECTED,
    RepairBlocker.TREE_CONTAINS_PROTECTED: RejectionReason.TREE_CONTAINS_PROTECTED,
}


def termination_order(
    target: ProcessIdentity, descendants: Sequence[Descendant]
) -> tuple[PlannedMember, ...]:
    """The target first, then descendants by increasing depth: a parent that supervises its
    children (nodemon, ``uvicorn --reload``) is gone before it could respawn them. Every
    member is a planned exact identity, so an orphaned child is still terminated."""
    ordered = sorted(descendants, key=lambda d: (d.depth, d.identity))
    return (PlannedMember(target, 0), *(PlannedMember(d.identity, d.depth) for d in ordered))


def rejection_for(blockers: Sequence[RepairBlocker]) -> RejectionReason:
    """The first blocker (in declared order) names the rejection."""
    if not blockers:
        raise ValueError("a rejection needs at least one blocker")
    return _REJECTION_FOR_BLOCKER[blockers[0]]


def member_outcome(attempt: TerminationAttempt, *, gone: bool) -> MemberOutcome:
    """Combine what the OS said with what was verified afterwards.

    A member that is verifiably gone is ``TERMINATED`` if we signalled it and
    ``ALREADY_GONE`` otherwise; an identity mismatch means the planned process was already
    gone and whatever reused its PID was not touched.
    """
    if gone:
        return (
            MemberOutcome.TERMINATED
            if attempt.outcome is TerminationOutcome.SIGNALLED
            else MemberOutcome.ALREADY_GONE
        )
    if attempt.outcome is TerminationOutcome.SIGNALLED:
        return MemberOutcome.STILL_RUNNING
    if attempt.outcome is TerminationOutcome.ACCESS_DENIED:
        return MemberOutcome.ACCESS_DENIED
    if attempt.outcome in (TerminationOutcome.ALREADY_GONE, TerminationOutcome.IDENTITY_MISMATCH):
        return MemberOutcome.ALREADY_GONE
    return MemberOutcome.ERROR


def repair_status(members: Sequence[MemberResult]) -> RepairStatus:
    """Success only when every member is verifiably gone."""
    if not members:
        raise ValueError("a repair needs at least one member")
    gone = sum(1 for m in members if m.outcome.gone)
    if gone == len(members):
        return RepairStatus.SUCCEEDED
    if gone == 0:
        return RepairStatus.FAILED
    return RepairStatus.PARTIAL


def appeared_since(
    planned: Set[ProcessIdentity], after: ProcessSnapshot, *, since: datetime
) -> tuple[ProcessIdentity, ...]:
    """Processes created after the plan whose parent PID is a planned member: identity drift."""
    planned_pids = {identity.pid for identity in planned}
    return tuple(
        sorted(
            o.identity
            for o in after.processes
            if o.identity not in planned
            and available(o.parent_pid)
            and o.parent_pid in planned_pids
            and o.identity.create_time >= since
        )
    )
