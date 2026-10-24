"""Risk of terminating a process or tree, from protection and tree context.

Product spec §11: an action is higher risk when it targets a Windows component, a process
in an active Claude/terminal ancestry (user intent is ambiguous), a process requiring
elevation, or a tree containing protected members. Any protection at all blocks the
generic terminate recipes; Windows components get their own explicit recipes later.
"""

from dataclasses import dataclass

from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.repair import RepairBlocker, RepairScope, RiskLevel
from windows_medic.domain.policies.protection import ProtectionLevel, ProtectionVerdict
from windows_medic.domain.policies.risk_markers import RiskMarker

_AMBIGUOUS_INTENT = frozenset({RiskMarker.CLAUDE_ANCESTRY, RiskMarker.TERMINAL_ANCESTRY})
_SERVICES_SESSION = 0


@dataclass(frozen=True, slots=True)
class RepairRisk:
    level: RiskLevel
    blockers: tuple[RepairBlocker, ...]
    requires_elevation: bool


def assess_repair_risk(
    observation: ProcessObservation,
    *,
    protection: ProtectionVerdict,
    risk_markers: tuple[RiskMarker, ...],
    scope: RepairScope,
) -> RepairRisk:
    """Assess terminating *observation* (or its tree). Total and deterministic."""
    levels = [RiskLevel.LOW]
    blockers: set[RepairBlocker] = set()

    if protection.level is ProtectionLevel.CRITICAL:
        levels.append(RiskLevel.CRITICAL)
        blockers.add(RepairBlocker.TARGET_PROTECTED)
    elif protection.level > ProtectionLevel.NONE:
        levels.append(RiskLevel.HIGH)
        blockers.add(RepairBlocker.TARGET_PROTECTED)

    if _AMBIGUOUS_INTENT & set(risk_markers):
        levels.append(RiskLevel.MEDIUM)

    if scope is RepairScope.TREE and RiskMarker.PROTECTED_DESCENDANT in risk_markers:
        levels.append(RiskLevel.HIGH)
        blockers.add(RepairBlocker.TREE_CONTAINS_PROTECTED)

    requires_elevation = not available(observation.username) or (
        not available(observation.session_id) or observation.session_id == _SERVICES_SESSION
    )
    if requires_elevation:
        levels.append(RiskLevel.MEDIUM)

    return RepairRisk(
        level=max(levels),
        blockers=tuple(blocker for blocker in RepairBlocker if blocker in blockers),
        requires_elevation=requires_elevation,
    )
