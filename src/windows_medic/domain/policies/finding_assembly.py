"""Shared bounds and small builders used by every finding policy.

Findings must be bounded by construction (they end up in model context), name the exact
processes they concern with the facts that limit what may be done to them, and describe
figures the same way everywhere.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta

from windows_medic.domain.models.evidence import Evidence
from windows_medic.domain.models.finding import AffectedProcess
from windows_medic.domain.models.metric import Metric, available
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.tree import ProcessTree
from windows_medic.domain.policies.protection import ProtectionPolicy, classify_protection
from windows_medic.domain.policies.risk_markers import AncestryPolicy, assess_risk_markers

_MIB = 1024**2
_MINUTES_PER_HOUR = 60


@dataclass(frozen=True, slots=True)
class FindingLimits:
    max_evidence: int
    max_affected_processes: int

    def __post_init__(self) -> None:
        if self.max_evidence < 1:
            raise ValueError("max_evidence must be at least 1")
        if self.max_affected_processes < 1:
            raise ValueError("max_affected_processes must be at least 1")

    def bound(self, evidence: Sequence[Evidence]) -> tuple[Evidence, ...]:
        return tuple(evidence[: self.max_evidence])


def affected_from_tree(
    identity: ProcessIdentity,
    tree: ProcessTree,
    *,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
    descendant_limit: int,
) -> AffectedProcess:
    """Describe a process that is present in *tree* with its protection and risk context."""
    observation = tree.observation(identity)
    return AffectedProcess(
        identity=identity,
        name=observation.name,
        exe_path=observation.exe_path,
        present=True,
        protection=classify_protection(observation, protection).level,
        risk_markers=assess_risk_markers(
            identity,
            tree,
            protection=protection,
            ancestry=ancestry,
            descendant_limit=descendant_limit,
        ),
    )


def describe(observation: ProcessObservation) -> str:
    return f"{label(observation.name)} (pid {observation.identity.pid})"


def label(name: Metric[str]) -> str:
    return name if available(name) else "unknown process"


def percent(value: float) -> str:
    return f"{value:.1f} %"


def mebibytes(value: int) -> str:
    return f"{value / _MIB:.0f} MiB"


def minutes(value: timedelta) -> str:
    total = int(value.total_seconds() // _MINUTES_PER_HOUR)
    if total >= _MINUTES_PER_HOUR:
        hours, rest = divmod(total, _MINUTES_PER_HOUR)
        return f"{hours} h {rest:02d} min"
    return f"{total} min"
