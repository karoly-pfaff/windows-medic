"""Listening sockets as a capability."""

from typing import Protocol

from windows_medic.domain.models.network import ListeningEndpoint


class NetworkReader(Protocol):
    """Reads the OS listener table. Owners are reported as PIDs, never identities."""

    def tcp_listeners(self) -> tuple[ListeningEndpoint, ...]:
        """Every TCP endpoint in the LISTEN state right now."""
        ...
