"""The real ``windows-medic-mcp`` server over stdio, driven by the official MCP client.

Only the project's own console script and test-owned child processes are involved. Pins
the transport contract (stdout belongs to MCP, stderr carries JSON logs only), every read
tool, input bounds over the wire, and the mutation tools end-to-end against controlled
targets.
"""

import json
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
import psutil
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

import windows_medic
import windows_medic_mcp
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic.infrastructure.windows.windows_process_reader import WindowsProcessReader

pytestmark = pytest.mark.windows_integration

INTERPRETER = getattr(sys, "_base_executable", sys.executable)
SERVER = Path(sys.executable).parent / "windows-medic-mcp.exe"
CHILD_LISTENER = (
    "import socket, time; s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); "
    "print(s.getsockname()[1], flush=True); time.sleep(120)"
)
SLEEPER = "import time; time.sleep(120)"


@pytest.fixture
def environ(tmp_path: Path) -> dict[str, str]:
    assert SERVER.is_file(), f"{SERVER} missing: run `uv sync --all-groups`"
    return {**os.environ, "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data")}


@pytest.fixture
def errlog(tmp_path: Path) -> Path:
    return tmp_path / "server-stderr.log"


@asynccontextmanager
async def _session(environ: dict[str, str], errlog_path: Path) -> AsyncIterator[ClientSession]:
    parameters = StdioServerParameters(command=str(SERVER), args=[], env=environ)
    with errlog_path.open("w+", encoding="utf-8") as errlog:
        async with (
            stdio_client(parameters, errlog=errlog) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            yield session


def _structured(result: CallToolResult) -> dict[str, Any]:
    assert result.is_error is not True, result.content
    assert result.structured_content is not None
    return dict(result.structured_content)


def _events(errlog_path: Path) -> list[str]:
    return [json.loads(line)["event"] for line in errlog_path.read_text("utf-8").splitlines()]


@pytest.fixture
def child_listener() -> Iterator[tuple[int, int]]:
    child = subprocess.Popen(
        [INTERPRETER, "-c", CHILD_LISTENER],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert child.stdout is not None
        yield child.pid, int(child.stdout.readline().strip())
    finally:
        _terminate_if_ours(child)


@pytest.fixture
def sleeper() -> Iterator[ProcessIdentity]:
    child = subprocess.Popen(
        [INTERPRETER, "-c", SLEEPER],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        reader = WindowsProcessReader(SystemClock())
        [match] = [o for o in reader.snapshot().processes if o.identity.pid == child.pid]
        yield match.identity
    finally:
        _terminate_if_ours(child)


def _terminate_if_ours(child: subprocess.Popen[Any]) -> None:
    if child.poll() is None:
        child.terminate()
    child.wait(timeout=30)
    if child.stdout is not None:
        child.stdout.close()


class TestTransport:
    def test_handshake_lists_the_v1_tools_and_logs_only_json_to_stderr(
        self, environ: dict[str, str], errlog: Path
    ) -> None:
        async def run() -> tuple[str, str, list[str]]:
            async with _session(environ, errlog) as session:
                info = await session.initialize()
                tools = await session.list_tools()
            return info.server_info.name, info.server_info.version, [t.name for t in tools.tools]

        name, version, tools = anyio.run(run)

        assert name == "windows-medic"
        assert version == windows_medic.__version__
        assert tools == [
            "get_system_health",
            "diagnose_slowdown",
            "inspect_process",
            "inspect_port",
            "list_recent_incidents",
            "terminate_process",
            "clear_port",
            "restart_windows_component",
        ]
        assert _events(errlog) == ["config.loaded", "mcp.server.starting"]


class TestReadTools:
    def test_every_read_tool_answers_with_bounded_structured_content(
        self, environ: dict[str, str], errlog: Path, child_listener: tuple[int, int]
    ) -> None:
        listener_pid, port = child_listener

        async def run() -> dict[str, dict[str, Any]]:
            async with _session(environ, errlog) as session:
                return {
                    "health": _structured(await session.call_tool("get_system_health", {})),
                    "process": _structured(
                        await session.call_tool("inspect_process", {"pid": os.getpid()})
                    ),
                    "port": _structured(await session.call_tool("inspect_port", {"port": port})),
                    "incidents": _structured(
                        await session.call_tool("list_recent_incidents", {"limit": 5})
                    ),
                    "diagnosis": _structured(
                        await session.call_tool("diagnose_slowdown", {"since_minutes": 5})
                    ),
                }

        answers = anyio.run(run)

        assert answers["health"]["process_count"] > 20
        assert len(answers["health"]["top_cpu"]) <= 5
        assert answers["process"]["process"]["process"]["pid"] == os.getpid()
        assert answers["process"]["protection"]["level"] in ("none", "protected")
        assert len(answers["process"]["descendants"]) <= 50
        assert answers["port"]["owners"][0]["process"]["pid"] == listener_pid
        assert answers["port"]["clear_port"]["eligible"] is True
        assert answers["incidents"]["incidents"] == []
        assert answers["diagnosis"]["evidence"]["processes_observed"] > 20
        assert len(answers["diagnosis"]["findings"]) <= 10
        assert "repair.started" not in _events(errlog)  # read tools mutate nothing


class TestBoundsOverTheWire:
    def test_invalid_arguments_are_structured_tool_failures(
        self, environ: dict[str, str], errlog: Path
    ) -> None:
        async def run() -> list[CallToolResult]:
            async with _session(environ, errlog) as session:
                return [
                    await session.call_tool("inspect_port", {"port": 70000}),
                    await session.call_tool("inspect_process", {"pid": -5}),
                    await session.call_tool("diagnose_slowdown", {"since_minutes": 100000}),
                    await session.call_tool("restart_windows_component", {"component": "winlogon"}),
                    await session.call_tool(
                        "terminate_process",
                        {"pid": os.getpid(), "create_time": "2026-09-11T09:00:00"},
                    ),
                    await session.call_tool("inspect_process", {"pid": 4_000_000}),
                ]

        results = anyio.run(run)

        assert all(r.is_error for r in results), results
        messages = [r.content[0].text for r in results if r.content[0].type == "text"]
        assert "65535" in messages[0]
        assert "greater than or equal to 0" in messages[1]
        assert "240" in messages[2]
        assert "'explorer' or 'dwm'" in messages[3]
        assert "timezone offset" in messages[4]
        assert "no process with pid 4000000 exists" in messages[5]
        assert "Traceback" not in "".join(messages)


class TestMutationTools:
    def test_a_controlled_process_is_inspected_and_terminated_end_to_end(
        self, environ: dict[str, str], errlog: Path, sleeper: ProcessIdentity
    ) -> None:
        async def run() -> tuple[dict[str, Any], dict[str, Any]]:
            async with _session(environ, errlog) as session:
                inspected = _structured(
                    await session.call_tool("inspect_process", {"pid": sleeper.pid})
                )
                create_time = inspected["process"]["process"]["create_time"]
                repaired = _structured(
                    await session.call_tool(
                        "terminate_process",
                        {"pid": sleeper.pid, "create_time": create_time, "scope": "process"},
                    )
                )
            return inspected, repaired

        inspected, repaired = anyio.run(run)

        assert datetime.fromisoformat(inspected["process"]["process"]["create_time"]) == (
            sleeper.create_time.astimezone(UTC)
        )
        assert repaired["mutation"] is True
        assert repaired["status"] == "succeeded", repaired
        assert repaired["after"]["members"][0]["outcome"] == "terminated"
        assert repaired["after"]["verification"]["passed"] is True
        assert not psutil.pid_exists(sleeper.pid) or _create_time_differs(sleeper)
        assert "repair.completed" in _events(errlog)

    def test_a_stale_identity_is_rejected_as_a_result(
        self, environ: dict[str, str], errlog: Path, sleeper: ProcessIdentity
    ) -> None:
        async def run() -> dict[str, Any]:
            async with _session(environ, errlog) as session:
                return _structured(
                    await session.call_tool(
                        "terminate_process",
                        {"pid": sleeper.pid, "create_time": "2001-01-01T00:00:00Z"},
                    )
                )

        repaired = anyio.run(run)

        assert repaired["status"] == "rejected"
        assert repaired["rejection"] == "stale_identity"
        assert psutil.pid_exists(sleeper.pid)

    def test_clear_port_frees_a_test_owned_port(
        self, environ: dict[str, str], errlog: Path, child_listener: tuple[int, int]
    ) -> None:
        listener_pid, port = child_listener

        async def run() -> dict[str, Any]:
            async with _session(environ, errlog) as session:
                return _structured(await session.call_tool("clear_port", {"port": port}))

        repaired = anyio.run(run)

        assert repaired["action"] == "port.clear"
        assert repaired["status"] == "succeeded", repaired
        assert repaired["after"]["members"][0]["process"]["pid"] == listener_pid
        assert f"port {port} has no listener" in repaired["after"]["verification"]["detail"]

    def test_dwm_restart_is_rejected_by_default_without_touching_anything(
        self, environ: dict[str, str], errlog: Path
    ) -> None:
        async def run() -> dict[str, Any]:
            async with _session(environ, errlog) as session:
                return _structured(
                    await session.call_tool("restart_windows_component", {"component": "dwm"})
                )

        repaired = anyio.run(run)

        assert repaired["status"] == "rejected"
        assert repaired["rejection"] == "high_risk_disabled"
        assert repaired["before"]["requires_elevation"] is True
        assert "repair.rejected" in _events(errlog)


def _create_time_differs(identity: ProcessIdentity) -> bool:
    try:
        actual = datetime.fromtimestamp(psutil.Process(identity.pid).create_time(), tz=UTC)
    except psutil.NoSuchProcess:
        return True
    return abs((actual - identity.create_time).total_seconds()) > 0.01


class TestInspectorWorkflow:
    def test_mcp_run_discovers_the_server_object_the_inspector_uses(
        self, environ: dict[str, str], errlog: Path
    ) -> None:
        """``mcp dev``/``mcp run`` load ``server.py`` and look for a ``server`` attribute."""
        module = Path(windows_medic_mcp.__file__).parent / "server.py"
        mcp_cli = Path(sys.executable).parent / "mcp.exe"
        assert mcp_cli.is_file()

        async def run() -> list[str]:
            parameters = StdioServerParameters(
                command=str(mcp_cli), args=["run", str(module)], env=environ
            )
            with errlog.open("w+", encoding="utf-8") as log:
                async with (
                    stdio_client(parameters, errlog=log) as (read, write),
                    ClientSession(read, write) as session,
                ):
                    await session.initialize()
                    tools = await session.list_tools()
                    health = _structured(await session.call_tool("get_system_health", {}))
            assert health["process_count"] > 20
            return [t.name for t in tools.tools]

        assert len(anyio.run(run)) == 8


def _server_pid(errlog_path: Path) -> int:
    for line in errlog_path.read_text("utf-8").splitlines():
        record = json.loads(line)
        if record.get("event") == "mcp.server.starting":
            pid = record["pid"]
            assert isinstance(pid, int)
            return pid
    raise AssertionError("the server never logged mcp.server.starting")


class TestRepeatedCalls:
    ROUNDS = 40
    MAX_GROWTH_BYTES = 24 * 1024 * 1024
    MAX_RESPONSE_BYTES = 64 * 1024

    def test_many_sequential_and_concurrent_reads_stay_bounded(
        self,
        environ: dict[str, str],
        errlog: Path,
        child_listener: tuple[int, int],
        tmp_path: Path,
    ) -> None:
        """One long session: repeated reads must not grow the server or degrade answers."""
        _, port = child_listener
        config = tmp_path / "config.toml"
        config.write_text("[health]\nmeasurement_window_seconds = 0.2\n", encoding="utf-8")
        environ = {**environ, "WINDOWS_MEDIC_CONFIG_FILE": str(config)}
        sizes: list[int] = []
        rss: list[int] = []

        async def read_round(session: ClientSession) -> None:
            calls = [
                ("get_system_health", {}),
                ("inspect_process", {"pid": os.getpid()}),
                ("inspect_port", {"port": port}),
                ("list_recent_incidents", {"limit": 5}),
            ]
            for name, arguments in calls:
                result = await session.call_tool(name, arguments)
                structured = _structured(result)
                sizes.append(len(json.dumps(structured)))

        async def run() -> None:
            async with _session(environ, errlog) as session:
                server = psutil.Process(_server_pid(errlog))
                for round_number in range(self.ROUNDS):
                    await read_round(session)
                    if round_number in (4, self.ROUNDS - 1):
                        rss.append(server.memory_info().rss)
                async with anyio.create_task_group() as group:
                    for _ in range(8):
                        group.start_soon(read_round, session)
                rss.append(server.memory_info().rss)

        anyio.run(run)

        assert len(sizes) == (self.ROUNDS + 8) * 4
        assert max(sizes) <= self.MAX_RESPONSE_BYTES, max(sizes)
        warm, sequential_end, concurrent_end = rss
        assert sequential_end - warm <= self.MAX_GROWTH_BYTES, rss
        assert concurrent_end - warm <= self.MAX_GROWTH_BYTES, rss
        events = _events(errlog)
        assert "repair.started" not in events
        assert not any(event.endswith(".crashed") for event in events)
