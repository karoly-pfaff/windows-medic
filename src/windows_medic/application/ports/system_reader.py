"""System-wide metrics as a capability."""

from typing import Protocol

from windows_medic.domain.models.samples import SystemObservation


class SystemReader(Protocol):
    """Reads one system-wide observation."""

    def snapshot(self) -> SystemObservation:
        """Read CPU, memory, commit, process count and disk counters right now."""
        ...
