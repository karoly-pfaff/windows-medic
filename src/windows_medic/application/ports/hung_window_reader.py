"""Windows' not-responding verdict about top-level windows, as a capability."""

from typing import Protocol

from windows_medic.domain.models.gui import HungWindow


class HungWindowReader(Protocol):
    """Reads which top-level windows Windows currently considers hung."""

    def hung_windows(self) -> tuple[HungWindow, ...]:
        """Bounded list of hung windows with their owner PIDs; empty when none are hung."""
        ...
