"""Eligibility of a port for the clear-port repair. Planning only; nothing is executed here."""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.policies.protection import ProtectionLevel


class ClearPortBlocker(StrEnum):
    """Declared in the order blockers are reported."""

    OWNER_PROTECTED = "owner_protected"
    OWNER_UNRESOLVED = "owner_unresolved"
    NO_OWNER = "no_owner"


@dataclass(frozen=True, slots=True)
class ClearPortEligibility:
    eligible: bool
    blockers: tuple[ClearPortBlocker, ...]


def assess_clear_port(
    *,
    resolved_levels: Sequence[tuple[ProcessIdentity, ProtectionLevel]],
    unresolved_count: int,
) -> ClearPortEligibility:
    """A port may be cleared only when every listener is resolved and unprotected."""
    blockers: set[ClearPortBlocker] = set()
    if any(level > ProtectionLevel.NONE for _, level in resolved_levels):
        blockers.add(ClearPortBlocker.OWNER_PROTECTED)
    if unresolved_count > 0:
        blockers.add(ClearPortBlocker.OWNER_UNRESOLVED)
    if not resolved_levels and unresolved_count == 0:
        blockers.add(ClearPortBlocker.NO_OWNER)
    ordered = tuple(blocker for blocker in ClearPortBlocker if blocker in blockers)
    return ClearPortEligibility(eligible=not ordered, blockers=ordered)
