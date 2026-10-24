"""Risk markers: facts about a process's place in the tree that raise the risk of acting on it.

Markers are evidence for later repair-risk and diagnosis policies. They never decide
anything on their own.
"""

from dataclasses import dataclass
from enum import StrEnum

from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.tree import ProcessTree, UnresolvedParent
from windows_medic.domain.policies.naming import candidate_names, lowered, mentions_marker
from windows_medic.domain.policies.protection import (
    ProtectionLevel,
    ProtectionPolicy,
    ProtectionReason,
    classify_protection,
)


class RiskMarker(StrEnum):
    """Declared in the order markers are reported."""

    CLAUDE_ANCESTRY = "claude_ancestry"
    WINDOWS_MEDIC_ANCESTRY = "windows_medic_ancestry"
    TERMINAL_ANCESTRY = "terminal_ancestry"
    UNRESOLVED_PARENT = "unresolved_parent"
    PROTECTED_DESCENDANT = "protected_descendant"


@dataclass(frozen=True, slots=True)
class AncestryPolicy:
    """Markers identifying Claude Code and interactive terminals among ancestors."""

    claude_markers: tuple[str, ...]
    terminal_process_names: tuple[str, ...]


def assess_risk_markers(
    identity: ProcessIdentity,
    tree: ProcessTree,
    *,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
    descendant_limit: int,
) -> tuple[RiskMarker, ...]:
    """Markers for *identity* within *tree*, unique and in :class:`RiskMarker` order."""
    found: set[RiskMarker] = set()
    terminals = lowered(ancestry.terminal_process_names)

    for ancestor in tree.ancestry_of(identity).ancestors:
        observation = tree.observation(ancestor)
        if _is_claude(observation, ancestry):
            found.add(RiskMarker.CLAUDE_ANCESTRY)
        if _is_windows_medic(observation, protection):
            found.add(RiskMarker.WINDOWS_MEDIC_ANCESTRY)
        if candidate_names(observation) & terminals:
            found.add(RiskMarker.TERMINAL_ANCESTRY)

    if isinstance(tree.parent_of(identity), UnresolvedParent):
        found.add(RiskMarker.UNRESOLVED_PARENT)

    for descendant in tree.descendants_of(identity, limit=descendant_limit):
        verdict = classify_protection(tree.observation(descendant.identity), protection)
        if verdict.level >= ProtectionLevel.PROTECTED:
            found.add(RiskMarker.PROTECTED_DESCENDANT)
            break

    return tuple(marker for marker in RiskMarker if marker in found)


def _is_claude(observation: ProcessObservation, ancestry: AncestryPolicy) -> bool:
    names = candidate_names(observation)
    return any(
        name.startswith(marker) for name in names for marker in lowered(ancestry.claude_markers)
    ) or mentions_marker(observation, ancestry.claude_markers)


def _is_windows_medic(observation: ProcessObservation, protection: ProtectionPolicy) -> bool:
    return (
        ProtectionReason.WINDOWS_MEDIC_SELF in classify_protection(observation, protection).reasons
    )
