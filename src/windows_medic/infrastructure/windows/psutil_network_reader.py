"""psutil-backed :class:`NetworkReader`.

One ``net_connections`` call reads the whole TCP table (``GetExtendedTcpTable`` underneath),
which reports the owning PID without elevation. Only LISTEN sockets are returned.
"""

import socket
from collections.abc import Callable, Sequence
from typing import Protocol

import psutil

from windows_medic.domain.errors import ObservationError
from windows_medic.domain.models.network import (
    AddressFamily,
    ListeningEndpoint,
    TransportProtocol,
)


class NetworkReadError(ObservationError):
    """The OS connection table could not be read."""


class _Connection(Protocol):
    """The subset of ``psutil._common.sconn`` this adapter relies on.

    ``laddr`` is an ``addr(ip, port)`` named tuple, or an empty tuple when unbound.
    """

    @property
    def family(self) -> int: ...
    @property
    def laddr(self) -> object: ...
    @property
    def status(self) -> str: ...
    @property
    def pid(self) -> int | None: ...


def _tcp_connections() -> Sequence[_Connection]:
    return psutil.net_connections(kind="tcp")


class PsutilNetworkReader:
    """Reads TCP listeners through psutil."""

    def __init__(
        self, *, connections: Callable[[], Sequence[_Connection]] = _tcp_connections
    ) -> None:
        self._connections = connections

    def tcp_listeners(self) -> tuple[ListeningEndpoint, ...]:
        try:
            connections = self._connections()
        except (psutil.Error, OSError) as exc:
            raise NetworkReadError(f"could not read the TCP connection table: {exc}") from exc
        endpoints: list[ListeningEndpoint] = []
        for connection in connections:
            if connection.status != psutil.CONN_LISTEN:
                continue
            ip = getattr(connection.laddr, "ip", None)
            port = getattr(connection.laddr, "port", None)
            if not isinstance(ip, str) or not isinstance(port, int):
                continue
            endpoints.append(
                ListeningEndpoint(
                    protocol=TransportProtocol.TCP,
                    family=_family(connection.family),
                    address=ip,
                    port=port,
                    owner_pid=connection.pid,
                )
            )
        return tuple(endpoints)


def _family(value: int) -> AddressFamily:
    return AddressFamily.IPV6 if value == socket.AF_INET6 else AddressFamily.IPV4
