"""PsutilNetworkReader maps the psutil connection table to listening endpoints."""

import socket
from collections import namedtuple

import psutil
import pytest

from windows_medic.domain.models.network import AddressFamily, TransportProtocol
from windows_medic.infrastructure.windows.psutil_network_reader import (
    NetworkReadError,
    PsutilNetworkReader,
)

Connection = namedtuple("Connection", ["family", "type", "laddr", "raddr", "status", "pid"])
Address = namedtuple("Address", ["ip", "port"])


def listening(ip: str, port: int, pid: int | None, family: int = socket.AF_INET) -> Connection:
    return Connection(family, socket.SOCK_STREAM, Address(ip, port), (), psutil.CONN_LISTEN, pid)


def established(port: int, pid: int) -> Connection:
    return Connection(
        socket.AF_INET,
        socket.SOCK_STREAM,
        Address("127.0.0.1", port),
        Address("10.0.0.1", 443),
        psutil.CONN_ESTABLISHED,
        pid,
    )


def test_maps_listening_sockets_of_both_families() -> None:
    reader = PsutilNetworkReader(
        connections=lambda: [
            listening("0.0.0.0", 5173, 100),  # noqa: S104 - test data
            listening("::", 5173, 100, family=socket.AF_INET6),
        ]
    )

    endpoints = reader.tcp_listeners()

    assert [(e.family, e.address, e.port, e.owner_pid) for e in endpoints] == [
        (AddressFamily.IPV4, "0.0.0.0", 5173, 100),  # noqa: S104 - test data
        (AddressFamily.IPV6, "::", 5173, 100),
    ]
    assert all(e.protocol is TransportProtocol.TCP for e in endpoints)


def test_only_listening_sockets_are_reported() -> None:
    reader = PsutilNetworkReader(connections=lambda: [established(5173, 100)])

    assert reader.tcp_listeners() == ()


def test_unknown_owner_pid_is_preserved_as_none() -> None:
    reader = PsutilNetworkReader(connections=lambda: [listening("127.0.0.1", 80, None)])

    assert reader.tcp_listeners()[0].owner_pid is None


def test_denied_connection_table_is_a_typed_error() -> None:
    def denied() -> list[Connection]:
        raise psutil.AccessDenied

    with pytest.raises(NetworkReadError, match="connection table"):
        PsutilNetworkReader(connections=denied).tcp_listeners()


def test_default_source_reads_the_real_table_without_raising() -> None:
    endpoints = PsutilNetworkReader().tcp_listeners()

    assert all(1 <= e.port <= 65535 for e in endpoints)
