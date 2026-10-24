"""User-logon startup registration as a capability (Task Scheduler on Windows)."""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class Registration(StrEnum):
    REGISTERED = "registered"
    NOT_REGISTERED = "not_registered"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class StartupState:
    registration: Registration
    command: str | None = None
    detail: str | None = None


class StartupRegistry(Protocol):
    """Registers one command to run, unelevated, when the current user logs on."""

    def register(self, command: Sequence[str]) -> None:
        """Create or replace the registration. Raises StartupRegistrationError."""
        ...

    def unregister(self) -> bool:
        """Remove the registration; ``False`` when there was none."""
        ...

    def state(self) -> StartupState:
        """What is registered right now; never raises for an absent registration."""
        ...

    def run_now(self) -> None:
        """Start the registered command immediately. Raises StartupRegistrationError."""
        ...
