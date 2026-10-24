"""Process tree: a snapshot graph over exact identities.

Windows keeps a child's parent PID even after the parent dies and the PID is reused.
A parent link is therefore resolved only when a process with that PID exists in the same
snapshot *and* was created no later than the child. Anything else is an explicit
:class:`UnresolvedParent`, which is evidence for later policies, not an orphan verdict.

Walks are bounded and cycle-guarded so corrupt observations cannot recurse forever.
"""

from collections import deque
from dataclasses import dataclass
from enum import StrEnum

from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.samples import ProcessSnapshot

MAX_ANCESTRY_DEPTH = 64
DEFAULT_DESCENDANT_LIMIT = 1000


class UnresolvedParentReason(StrEnum):
    PARENT_GONE = "parent_gone"
    PARENT_PID_REUSED = "parent_pid_reused"
    PARENT_UNKNOWN = "parent_unknown"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class UnresolvedParent:
    """The parent PID the kernel reports, and why it could not be trusted as a link."""

    parent_pid: int | None
    reason: UnresolvedParentReason


type ParentLink = ProcessIdentity | UnresolvedParent


class AncestryEnd(StrEnum):
    UNRESOLVED = "unresolved"
    CYCLE = "cycle"
    DEPTH_LIMIT = "depth_limit"


@dataclass(frozen=True, slots=True)
class Ancestry:
    """Ancestors nearest-first, why the walk stopped, and the topmost unresolved link.

    ``top_link`` is the unresolved parent of the last node reached (the start node itself
    when it has no resolvable parent); it is ``None`` for cycle/depth stops.
    """

    ancestors: tuple[ProcessIdentity, ...]
    end: AncestryEnd
    top_link: UnresolvedParent | None


@dataclass(frozen=True, slots=True)
class Descendant:
    identity: ProcessIdentity
    depth: int


@dataclass(frozen=True, slots=True)
class ProcessTree:
    """Immutable graph built from one snapshot. Use :func:`build_process_tree`."""

    _observations: dict[ProcessIdentity, ProcessObservation]
    _parents: dict[ProcessIdentity, ParentLink]
    _children: dict[ProcessIdentity, tuple[ProcessIdentity, ...]]

    def contains(self, identity: ProcessIdentity) -> bool:
        return identity in self._observations

    def observation(self, identity: ProcessIdentity) -> ProcessObservation:
        return self._observations[identity]

    def parent_of(self, identity: ProcessIdentity) -> ParentLink:
        return self._parents[identity]

    def children_of(self, identity: ProcessIdentity) -> tuple[ProcessIdentity, ...]:
        return self._children.get(identity, ())

    def roots(self) -> tuple[ProcessIdentity, ...]:
        return tuple(
            sorted(i for i, link in self._parents.items() if isinstance(link, UnresolvedParent))
        )

    def ancestry_of(self, identity: ProcessIdentity) -> Ancestry:
        """Walk resolved parent links upward; bounded and cycle-guarded."""
        visited = {identity}
        ancestors: list[ProcessIdentity] = []
        current = identity
        while True:
            link = self.parent_of(current)
            if isinstance(link, UnresolvedParent):
                return Ancestry(tuple(ancestors), AncestryEnd.UNRESOLVED, link)
            if link in visited:
                return Ancestry(tuple(ancestors), AncestryEnd.CYCLE, None)
            if len(ancestors) >= MAX_ANCESTRY_DEPTH:
                return Ancestry(tuple(ancestors), AncestryEnd.DEPTH_LIMIT, None)
            ancestors.append(link)
            visited.add(link)
            current = link

    def descendants_of(
        self, identity: ProcessIdentity, *, limit: int = DEFAULT_DESCENDANT_LIMIT
    ) -> tuple[Descendant, ...]:
        """Breadth-first descendants with depth, bounded by *limit*."""
        found: list[Descendant] = []
        visited = {identity}
        queue = deque((child, 1) for child in self.children_of(identity))
        while queue and len(found) < limit:
            current, depth = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            found.append(Descendant(current, depth))
            queue.extend((child, depth + 1) for child in self.children_of(current))
        return tuple(found)


def build_process_tree(snapshot: ProcessSnapshot) -> ProcessTree:
    """Resolve parent links for every observation in *snapshot*."""
    observations: dict[ProcessIdentity, ProcessObservation] = {}
    for observation in snapshot.processes:
        if observation.identity in observations:
            raise ValueError(f"duplicate identity in snapshot: {observation.identity}")
        observations[observation.identity] = observation
    by_pid = {identity.pid: identity for identity in observations}

    parents = {identity: _resolve_parent(obs, by_pid) for identity, obs in observations.items()}
    children: dict[ProcessIdentity, list[ProcessIdentity]] = {}
    for identity, link in parents.items():
        if isinstance(link, ProcessIdentity):
            children.setdefault(link, []).append(identity)
    return ProcessTree(
        observations, parents, {parent: tuple(sorted(kids)) for parent, kids in children.items()}
    )


def _resolve_parent(
    observation: ProcessObservation, by_pid: dict[int, ProcessIdentity]
) -> ParentLink:
    if not available(observation.parent_pid):
        return UnresolvedParent(None, UnresolvedParentReason.PARENT_UNKNOWN)
    parent_pid = observation.parent_pid
    if parent_pid == observation.identity.pid:
        return UnresolvedParent(parent_pid, UnresolvedParentReason.INVALID)
    candidate = by_pid.get(parent_pid)
    if candidate is None:
        return UnresolvedParent(parent_pid, UnresolvedParentReason.PARENT_GONE)
    if candidate.create_time > observation.identity.create_time:
        return UnresolvedParent(parent_pid, UnresolvedParentReason.PARENT_PID_REUSED)
    return candidate
