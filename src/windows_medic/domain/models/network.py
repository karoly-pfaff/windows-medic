"""Network endpoints as observed from the OS connection table."""

from dataclasses import dataclass
from enum import StrEnum

MIN_PORT = 1
MAX_PORT = 65535


class TransportProtocol(StrEnum):
    TCP = "tcp"


class AddressFamily(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True, slots=True)
class ListeningEndpoint:
    """One listening socket. ``owner_pid`` is what the OS reported; it is not an identity."""

    protocol: TransportProtocol
    family: AddressFamily
    address: str
    port: int
    owner_pid: int | None

    def __post_init__(self) -> None:
        if not MIN_PORT <= self.port <= MAX_PORT:
            raise ValueError(f"port must be between {MIN_PORT} and {MAX_PORT}, got {self.port}")
