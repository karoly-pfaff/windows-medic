"""Inspect one process: identity-validated lookup plus bounded tree, protection and risk.

One snapshot feeds everything so the tree context is consistent with the observation. The
requested ``create_time`` is optional (the MCP surface allows PID-only lookups) but when
given it is enforced: a mismatch is a stale identity, never a silent re-target.
"""

from dataclasses import dataclass
from datetime import datetime

from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.domain.errors import ProcessNotFoundError, StaleIdentityError
from windows_medic.domain.models.metric import Metric
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.tree import (
    DEFAULT_DESCENDANT_LIMIT,
    AncestryEnd,
    ParentLink,
    ProcessTree,
    build_process_tree,
)
from windows_medic.domain.policies.protection import (
    ProtectionLevel,
    ProtectionPolicy,
    ProtectionVerdict,
    classify_protection,
)
from windows_medic.domain.policies.risk_markers import (
    AncestryPolicy,
    RiskMarker,
    assess_risk_markers,
)


@dataclass(frozen=True, slots=True)
class InspectionLimits:
    """Bounds on the tree context returned by one inspection."""

    max_ancestors: int
    max_descendants: int
    max_port_owners: int = 8

    def __post_init__(self) -> None:
        if self.max_ancestors < 0:
            raise ValueError("max_ancestors cannot be negative")
        if self.max_descendants < 0:
            raise ValueError("max_descendants cannot be negative")
        if self.max_port_owners < 1:
            raise ValueError("max_port_owners must be at least 1")


@dataclass(frozen=True, slots=True)
class RelatedProcess:
    """An ancestor (depth 1 = parent) or descendant (depth 1 = child) of the target."""

    identity: ProcessIdentity
    name: Metric[str]
    protection: ProtectionLevel
    depth: int


@dataclass(frozen=True, slots=True)
class ProcessInspection:
    """Typed result of :class:`InspectProcess`. Bounded by construction."""

    observed_at: datetime
    observation: ProcessObservation
    parent: ParentLink
    ancestors: tuple[RelatedProcess, ...]
    ancestors_truncated: bool
    ancestry_end: AncestryEnd
    descendants: tuple[RelatedProcess, ...]
    descendants_truncated: bool
    protection: ProtectionVerdict
    risk_markers: tuple[RiskMarker, ...]


class InspectProcess:
    """Describe one process and its place in the current process tree."""

    def __init__(
        self,
        *,
        process_reader: ProcessReader,
        protection: ProtectionPolicy,
        ancestry: AncestryPolicy,
        limits: InspectionLimits,
    ) -> None:
        self._process_reader = process_reader
        self._protection = protection
        self._ancestry = ancestry
        self._limits = limits

    @property
    def limits(self) -> InspectionLimits:
        return self._limits

    def execute(self, pid: int, create_time: datetime | None = None) -> ProcessInspection:
        """Inspect *pid*, optionally insisting on the exact *create_time*.

        Raises:
            ValueError: If *pid* is negative (a boundary validation bug, not an outcome).
            ProcessNotFoundError: If no process with *pid* exists.
            StaleIdentityError: If *create_time* was given and the PID now belongs to a
                different process instance.
        """
        if pid < 0:
            raise ValueError(f"pid must be non-negative, got {pid}")
        snapshot = self._process_reader.snapshot()
        target = next((o for o in snapshot.processes if o.identity.pid == pid), None)
        if target is None:
            raise ProcessNotFoundError(pid)
        if create_time is not None and target.identity.create_time != create_time:
            raise StaleIdentityError(ProcessIdentity(pid, create_time), target.identity)

        tree = build_process_tree(snapshot)
        ancestry = tree.ancestry_of(target.identity)
        descendants = tree.descendants_of(target.identity, limit=self._limits.max_descendants + 1)
        return ProcessInspection(
            observed_at=snapshot.observed_at,
            observation=target,
            parent=tree.parent_of(target.identity),
            ancestors=tuple(
                self._related(tree, identity, depth)
                for depth, identity in enumerate(
                    ancestry.ancestors[: self._limits.max_ancestors], start=1
                )
            ),
            ancestors_truncated=len(ancestry.ancestors) > self._limits.max_ancestors,
            ancestry_end=ancestry.end,
            descendants=tuple(
                self._related(tree, d.identity, d.depth)
                for d in descendants[: self._limits.max_descendants]
            ),
            descendants_truncated=len(descendants) > self._limits.max_descendants,
            protection=classify_protection(target, self._protection),
            risk_markers=assess_risk_markers(
                target.identity,
                tree,
                protection=self._protection,
                ancestry=self._ancestry,
                # Risk evidence scans the whole (bounded) subtree, not just what is shown.
                descendant_limit=DEFAULT_DESCENDANT_LIMIT,
            ),
        )

    def _related(self, tree: ProcessTree, identity: ProcessIdentity, depth: int) -> RelatedProcess:
        return related_process(tree, identity, depth, self._protection)


def related_process(
    tree: ProcessTree, identity: ProcessIdentity, depth: int, policy: ProtectionPolicy
) -> RelatedProcess:
    """Summarise a tree member for inclusion in an inspection result."""
    observation = tree.observation(identity)
    return RelatedProcess(
        identity=identity,
        name=observation.name,
        protection=classify_protection(observation, policy).level,
        depth=depth,
    )
