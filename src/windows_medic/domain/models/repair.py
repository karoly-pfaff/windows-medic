"""Repairs: candidates (planning), and records of attempted repairs (execution + audit).

A candidate names a recipe, an exact target identity, the assessed risk and the blockers
that currently make it ineligible. It always references the evidence it was derived from;
a repair is never suggested on a hunch.

A record is the audit of one attempt: what was asked, whether policy rejected it before
any OS call, what happened to every member of the target tree, which members appeared
after the plan (identity drift), and whether the postcondition was verified. A repair is
never successful because a call returned; it is successful because the postcondition
was observed.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from windows_medic.domain.models.evidence import Evidence
from windows_medic.domain.models.metric import Metric
from windows_medic.domain.models.process import ProcessIdentity


class RepairAction(StrEnum):
    """Recipe ids. A fixed allowlist, never user-extensible."""

    PROCESS_TERMINATE = "process.terminate"
    PROCESS_TERMINATE_TREE = "process.terminate_tree"
    PORT_CLEAR = "port.clear"
    WINDOWS_EXPLORER_RESTART = "windows.explorer.restart"
    WINDOWS_DWM_RESTART = "windows.dwm.restart"


class RepairScope(StrEnum):
    PROCESS = "process"
    TREE = "tree"


class RiskLevel(StrEnum):
    """Ordered: ``LOW < MEDIUM < HIGH < CRITICAL``. High and above are never automatic."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RISK_RANKS[self]

    def __lt__(self, other: object) -> bool:
        return self.rank < other.rank if isinstance(other, RiskLevel) else NotImplemented

    def __le__(self, other: object) -> bool:
        return self.rank <= other.rank if isinstance(other, RiskLevel) else NotImplemented

    def __gt__(self, other: object) -> bool:
        return self.rank > other.rank if isinstance(other, RiskLevel) else NotImplemented

    def __ge__(self, other: object) -> bool:
        return self.rank >= other.rank if isinstance(other, RiskLevel) else NotImplemented


_RISK_RANKS = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class RepairBlocker(StrEnum):
    """Declared in the order blockers are reported."""

    TARGET_PROTECTED = "target_protected"
    TREE_CONTAINS_PROTECTED = "tree_contains_protected"


@dataclass(frozen=True, slots=True)
class RepairCandidate:
    action: RepairAction
    target: ProcessIdentity
    scope: RepairScope
    risk: RiskLevel
    requires_elevation: bool
    blockers: tuple[RepairBlocker, ...]
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("a repair candidate must reference the evidence it is based on")

    @property
    def eligible(self) -> bool:
        return not self.blockers


class RepairStatus(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    REJECTED = "rejected"


class RejectionReason(StrEnum):
    """Why policy refused to act, decided before any OS call."""

    TARGET_NOT_FOUND = "target_not_found"
    STALE_IDENTITY = "stale_identity"
    TARGET_PROTECTED = "target_protected"
    TREE_CONTAINS_PROTECTED = "tree_contains_protected"
    TREE_TOO_LARGE = "tree_too_large"
    PORT_NOT_LISTENING = "port_not_listening"
    PORT_OWNER_UNRESOLVED = "port_owner_unresolved"
    PORT_OWNER_PROTECTED = "port_owner_protected"
    PORT_OWNER_CHANGED = "port_owner_changed"
    HIGH_RISK_DISABLED = "high_risk_disabled"
    SESSION_UNKNOWN = "session_unknown"
    COMPONENT_NOT_FOUND = "component_not_found"


class TerminationOutcome(StrEnum):
    """What the operating system said when asked to terminate one exact identity."""

    SIGNALLED = "signalled"
    ALREADY_GONE = "already_gone"
    ACCESS_DENIED = "access_denied"
    IDENTITY_MISMATCH = "identity_mismatch"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class TerminationAttempt:
    outcome: TerminationOutcome
    detail: str | None = None


class MemberOutcome(StrEnum):
    """What verifiably happened to one member of the target tree."""

    TERMINATED = "terminated"
    ALREADY_GONE = "already_gone"
    ACCESS_DENIED = "access_denied"
    STILL_RUNNING = "still_running"
    ERROR = "error"
    # Signalled (or not), but the result could not be observed afterwards: never "gone".
    UNVERIFIED = "unverified"

    @property
    def gone(self) -> bool:
        return self in _GONE_OUTCOMES


_GONE_OUTCOMES = frozenset({MemberOutcome.TERMINATED, MemberOutcome.ALREADY_GONE})


@dataclass(frozen=True, slots=True)
class PlannedMember:
    identity: ProcessIdentity
    depth: int


@dataclass(frozen=True, slots=True)
class MemberResult:
    identity: ProcessIdentity
    name: Metric[str]
    depth: int
    outcome: MemberOutcome
    detail: str | None


@dataclass(frozen=True, slots=True)
class Verification:
    """The observed postcondition, never the return code of a call."""

    passed: bool
    detail: str
    checked_at: datetime


@dataclass(frozen=True, slots=True)
class RepairRecord:
    """Audit of one repair attempt: rejected, succeeded, partial or failed."""

    id: str
    action: RepairAction
    scope: RepairScope
    status: RepairStatus
    requested_at: datetime
    completed_at: datetime | None
    target: ProcessIdentity | None
    port: int | None
    risk: RiskLevel | None
    requires_elevation: bool
    rejection: RejectionReason | None
    members: tuple[MemberResult, ...]
    appeared: tuple[ProcessIdentity, ...]
    verification: Verification | None
    replacement: ProcessIdentity | None = None
    """The new instance observed after a component restart, when one was verified."""


def new_repair_id() -> str:
    return uuid.uuid4().hex
