"""Inspect a TCP port: who listens on it, by exact identity, with races made explicit.

The listener table reports PIDs only. The use case therefore takes a process baseline
*before* reading the table, maps each reported PID to the identity it had at baseline, and
re-resolves that exact identity *after*. An owner that cannot be confirmed this way is
reported as unresolved rather than as whichever process now holds the PID.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from windows_medic.application.ports.network_reader import NetworkReader
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.use_cases.inspect_process import (
    InspectionLimits,
    RelatedProcess,
    related_process,
)
from windows_medic.domain.models.metric import Metric
from windows_medic.domain.models.network import MAX_PORT, MIN_PORT, ListeningEndpoint
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.tree import (
    DEFAULT_DESCENDANT_LIMIT,
    ParentLink,
    ProcessTree,
    build_process_tree,
)
from windows_medic.domain.policies.port_clearing import ClearPortEligibility, assess_clear_port
from windows_medic.domain.policies.protection import (
    ProtectionPolicy,
    ProtectionVerdict,
    classify_protection,
)
from windows_medic.domain.policies.risk_markers import (
    AncestryPolicy,
    RiskMarker,
    assess_risk_markers,
)


class UnresolvedOwnerReason(StrEnum):
    OWNER_UNKNOWN = "owner_unknown"
    OWNER_UNVERIFIED = "owner_unverified"
    OWNER_CHANGED = "owner_changed"


@dataclass(frozen=True, slots=True)
class UnresolvedOwner:
    """A listener whose owning process could not be pinned to an exact identity."""

    endpoint: ListeningEndpoint
    reported_pid: int | None
    reason: UnresolvedOwnerReason


@dataclass(frozen=True, slots=True)
class PortOwner:
    """A confirmed listener identity with its tree, protection and risk context."""

    identity: ProcessIdentity
    observation: ProcessObservation
    endpoints: tuple[ListeningEndpoint, ...]
    name: Metric[str]
    exe_path: Metric[str]
    command_line: Metric[tuple[str, ...]]
    username: Metric[str]
    parent: ParentLink
    ancestors: tuple[RelatedProcess, ...]
    ancestors_truncated: bool
    protection: ProtectionVerdict
    risk_markers: tuple[RiskMarker, ...]


@dataclass(frozen=True, slots=True)
class PortInspection:
    """Typed result of :class:`InspectPort`. Bounded by construction."""

    port: int
    observed_at: datetime
    owners: tuple[PortOwner, ...]
    unresolved: tuple[UnresolvedOwner, ...]
    truncated: bool
    clear_port: ClearPortEligibility


class InspectPort:
    """Resolve the listeners on one TCP port to exact identities."""

    def __init__(
        self,
        *,
        process_reader: ProcessReader,
        network_reader: NetworkReader,
        protection: ProtectionPolicy,
        ancestry: AncestryPolicy,
        limits: InspectionLimits,
    ) -> None:
        self._process_reader = process_reader
        self._network_reader = network_reader
        self._protection = protection
        self._ancestry = ancestry
        self._limits = limits

    @property
    def limits(self) -> InspectionLimits:
        return self._limits

    def execute(self, port: int) -> PortInspection:
        """Inspect *port*.

        Raises:
            ValueError: If *port* is outside 1-65535 (a boundary validation bug).
        """
        if not MIN_PORT <= port <= MAX_PORT:
            raise ValueError(f"port must be between {MIN_PORT} and {MAX_PORT}, got {port}")

        baseline = self._process_reader.snapshot()
        listeners = [e for e in self._network_reader.tcp_listeners() if e.port == port]
        by_pid = {o.identity.pid: o for o in baseline.processes}

        confirmed: dict[ProcessIdentity, list[ListeningEndpoint]] = {}
        unresolved: list[UnresolvedOwner] = []
        for endpoint in listeners:
            pid = endpoint.owner_pid
            if pid is None:
                unresolved.append(
                    UnresolvedOwner(endpoint, None, UnresolvedOwnerReason.OWNER_UNKNOWN)
                )
                continue
            at_baseline = by_pid.get(pid)
            if at_baseline is None:
                unresolved.append(
                    UnresolvedOwner(endpoint, pid, UnresolvedOwnerReason.OWNER_UNVERIFIED)
                )
                continue
            if at_baseline.identity in confirmed:
                confirmed[at_baseline.identity].append(endpoint)
                continue
            if self._process_reader.get(at_baseline.identity) is None:
                unresolved.append(
                    UnresolvedOwner(endpoint, pid, UnresolvedOwnerReason.OWNER_CHANGED)
                )
                continue
            confirmed[at_baseline.identity] = [endpoint]

        tree = build_process_tree(baseline)
        ordered = sorted(confirmed)
        shown = ordered[: self._limits.max_port_owners]
        truncated = len(ordered) > len(shown)
        owners = tuple(
            self._owner(tree, identity, tuple(confirmed[identity])) for identity in shown
        )
        return PortInspection(
            port=port,
            observed_at=baseline.observed_at,
            owners=owners,
            unresolved=tuple(unresolved),
            truncated=truncated,
            clear_port=assess_clear_port(
                resolved_levels=[(o.identity, o.protection.level) for o in owners],
                unresolved_count=len(unresolved) + (len(ordered) - len(shown)),
            ),
        )

    def _owner(
        self, tree: ProcessTree, identity: ProcessIdentity, endpoints: tuple[ListeningEndpoint, ...]
    ) -> PortOwner:
        observation = tree.observation(identity)
        ancestry = tree.ancestry_of(identity)
        return PortOwner(
            identity=identity,
            observation=observation,
            endpoints=endpoints,
            name=observation.name,
            exe_path=observation.exe_path,
            command_line=observation.command_line,
            username=observation.username,
            parent=tree.parent_of(identity),
            ancestors=tuple(
                related_process(tree, ancestor, depth, self._protection)
                for depth, ancestor in enumerate(
                    ancestry.ancestors[: self._limits.max_ancestors], start=1
                )
            ),
            ancestors_truncated=len(ancestry.ancestors) > self._limits.max_ancestors,
            protection=classify_protection(observation, self._protection),
            risk_markers=assess_risk_markers(
                identity,
                tree,
                protection=self._protection,
                ancestry=self._ancestry,
                descendant_limit=DEFAULT_DESCENDANT_LIMIT,
            ),
        )
