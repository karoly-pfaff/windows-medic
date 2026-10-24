"""Candidate repairs for a process a finding points at. Planning only.

The generic recipes are ``process.terminate`` and, when the target has children,
``process.terminate_tree``. Both are assessed with the current tree; blocked candidates
are reported with their blockers rather than silently dropped so the reason is visible.
"""

from windows_medic.domain.models.evidence import Evidence
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import RepairAction, RepairCandidate, RepairScope
from windows_medic.domain.models.tree import DEFAULT_DESCENDANT_LIMIT, ProcessTree
from windows_medic.domain.policies.protection import ProtectionPolicy, classify_protection
from windows_medic.domain.policies.repair_risk import assess_repair_risk
from windows_medic.domain.policies.risk_markers import AncestryPolicy, assess_risk_markers

_ACTION_FOR_SCOPE = {
    RepairScope.PROCESS: RepairAction.PROCESS_TERMINATE,
    RepairScope.TREE: RepairAction.PROCESS_TERMINATE_TREE,
}


def plan_termination(
    identity: ProcessIdentity,
    tree: ProcessTree,
    *,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
    evidence: tuple[Evidence, ...],
    descendant_limit: int = DEFAULT_DESCENDANT_LIMIT,
) -> tuple[RepairCandidate, ...]:
    """Process-scope candidate, plus a tree-scope one when *identity* has children."""
    observation = tree.observation(identity)
    verdict = classify_protection(observation, protection)
    markers = assess_risk_markers(
        identity,
        tree,
        protection=protection,
        ancestry=ancestry,
        descendant_limit=descendant_limit,
    )
    scopes = [RepairScope.PROCESS]
    if tree.children_of(identity):
        scopes.append(RepairScope.TREE)

    candidates: list[RepairCandidate] = []
    for scope in scopes:
        risk = assess_repair_risk(
            observation, protection=verdict, risk_markers=markers, scope=scope
        )
        candidates.append(
            RepairCandidate(
                action=_ACTION_FOR_SCOPE[scope],
                target=identity,
                scope=scope,
                risk=risk.level,
                requires_elevation=risk.requires_elevation,
                blockers=risk.blockers,
                evidence=evidence,
            )
        )
    return tuple(candidates)
