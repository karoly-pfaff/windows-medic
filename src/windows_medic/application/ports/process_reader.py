"""Process inventory as a capability. Identities are always ``(pid, create_time)``."""

from typing import Protocol

from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.samples import ProcessSnapshot


class ProcessReader(Protocol):
    """Reads process observations tolerant of exits and denied fields."""

    def snapshot(self) -> ProcessSnapshot:
        """Observe every process that can be identified; never fails because one cannot."""
        ...

    def get(self, identity: ProcessIdentity) -> ProcessObservation | None:
        """Observe exactly *identity*.

        Returns ``None`` when it is gone or its PID now belongs to a different process.
        """
        ...
