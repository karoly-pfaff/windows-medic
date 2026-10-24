"""Starting a Windows shell component as a capability (Explorer only; DWM is never started)."""

from typing import Protocol

from windows_medic.domain.models.component import StartAttempt, WindowsComponent


class ComponentController(Protocol):
    """Starts a component from its fixed system location with no arguments."""

    def start(self, component: WindowsComponent) -> StartAttempt:
        """Start *component*; a component that must never be started returns a refusal."""
        ...
