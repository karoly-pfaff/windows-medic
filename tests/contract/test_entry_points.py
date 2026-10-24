"""Entry points: agent, MCP server and CLI bootstrap configuration, run, and stop.

The agent runs the monitoring supervisor for a bounded duration; the MCP server builds
its tool set from the composed container and serves it over the injected transport.
"""

import asyncio
import io
import json
import logging
import os
import subprocess
import sys
from collections.abc import Iterator, Mapping
from datetime import timedelta
from pathlib import Path
from typing import TextIO

import anyio
import pytest
from mcp.server.mcpserver import MCPServer

import windows_medic
from tests.builders import process_snapshot, system
from tests.containers import fake_container
from tests.fakes import FakeProcessReader, FakeSystemReader
from windows_medic.domain.policies.adaptive_sampling import AdaptivePolicy
from windows_medic.domain.policies.pressure import PressureThresholds
from windows_medic.infrastructure.windows.single_instance import NamedMutexGuard, mutex_name
from windows_medic_agent import main as agent_main
from windows_medic_agent.evidence import EvidenceRetention, RollingEvidence
from windows_medic_agent.monitor import Monitor, SamplingIntervals
from windows_medic_cli import main as cli_main
from windows_medic_mcp import server as mcp_server
from windows_medic_root.container import Container, try_compose

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def root_logger_state() -> Iterator[None]:
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


@pytest.fixture
def environ(tmp_path: Path) -> dict[str, str]:
    return {"WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data")}


@pytest.fixture
def broken_environ(environ: dict[str, str]) -> dict[str, str]:
    return {**environ, "WINDOWS_MEDIC_LOG_LEVEL": "LOUD"}


def _json_events(stream: io.StringIO) -> list[str]:
    events: list[str] = []
    for line in stream.getvalue().splitlines():
        record = json.loads(line)
        assert isinstance(record, dict)
        assert isinstance(record["event"], str)
        events.append(record["event"])
    return events


class TestCli:
    def test_version_flag(self, environ: dict[str, str]) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()

        code = cli_main.main(["--version"], environ=environ, stdout=stdout, stderr=stderr)

        assert code == 0
        assert stdout.getvalue().strip() == f"windows-medic {windows_medic.__version__}"

    def test_no_arguments_reports_foundation_status(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()

        code = cli_main.main([], environ=environ, stdout=stdout, stderr=stderr)

        output = stdout.getvalue()
        assert code == 0
        assert f"windows-medic {windows_medic.__version__}" in output
        assert str(tmp_path / "data") in output
        assert "built-in defaults" in output
        assert "Commands: health, diagnose, inspect" in output

    def test_logs_go_to_stderr_as_json_not_stdout(self, environ: dict[str, str]) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()

        cli_main.main([], environ=environ, stdout=stdout, stderr=stderr)

        assert "config.loaded" in _json_events(stderr)
        assert not any(line.startswith("{") for line in stdout.getvalue().splitlines())

    def test_configuration_error_is_reported_on_stderr_with_exit_code_2(
        self, broken_environ: dict[str, str]
    ) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()

        code = cli_main.main([], environ=broken_environ, stdout=stdout, stderr=stderr)

        assert code == 2
        assert stdout.getvalue() == ""
        assert "windows-medic: configuration error" in stderr.getvalue()
        assert "logging.level" in stderr.getvalue()

    def test_unknown_argument_is_a_usage_error(self, environ: dict[str, str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            cli_main.main(["--bogus"], environ=environ, stdout=io.StringIO(), stderr=io.StringIO())

        assert excinfo.value.code == 2

    def test_python_dash_m_runs_the_cli(self, environ: dict[str, str]) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "windows_medic_cli", "--version"],
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO_ROOT,
            env={**environ, "SYSTEMROOT": "C:\\Windows", "PATH": ""},
            timeout=60,
        )

        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == f"windows-medic {windows_medic.__version__}"


class TestAgent:
    def test_version_flag(self, environ: dict[str, str]) -> None:
        stdout = io.StringIO()

        code = agent_main.main(["--version"], environ=environ, stdout=stdout, stderr=io.StringIO())

        assert code == 0
        assert stdout.getvalue().strip() == f"windows-medic-agent {windows_medic.__version__}"

    def test_streams_default_to_the_process_streams(
        self, environ: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stdout = io.StringIO()
        monkeypatch.setattr(sys, "stdout", stdout)

        code = agent_main.main(["--version"], environ=environ)

        assert code == 0
        assert stdout.getvalue().strip() == f"windows-medic-agent {windows_medic.__version__}"

    def test_runs_the_monitor_for_the_requested_duration_and_exits_zero(
        self, environ: dict[str, str]
    ) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()

        code = agent_main.main(
            ["--duration", "0.3"],
            environ=environ,
            stdout=stdout,
            stderr=stderr,
            build=_synthetic_monitor,
        )

        events = _json_events(stderr)
        assert code == 0
        assert stdout.getvalue() == ""
        assert events[:2] == ["config.loaded", "agent.started"]
        assert "agent.monitor.started" in events
        assert "agent.health" in events
        assert events[-2:] == ["agent.monitor.stopped", "agent.stopped"]

    def test_keyboard_interrupt_stops_gracefully(self, environ: dict[str, str]) -> None:
        stderr = io.StringIO()

        code = agent_main.main(
            [], environ=environ, stdout=io.StringIO(), stderr=stderr, build=_interrupting_monitor
        )

        assert code == 0
        assert _json_events(stderr)[-1] == "agent.stopped"

    def test_configuration_error_exits_with_code_2(self, broken_environ: dict[str, str]) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()

        code = agent_main.main([], environ=broken_environ, stdout=stdout, stderr=stderr)

        assert code == 2
        assert "windows-medic-agent: configuration error" in stderr.getvalue()

    @pytest.mark.parametrize("value", ["0", "-1", "soon"])
    def test_invalid_duration_is_a_usage_error(self, environ: dict[str, str], value: str) -> None:
        with pytest.raises(SystemExit) as excinfo:
            agent_main.main(
                ["--duration", value], environ=environ, stdout=io.StringIO(), stderr=io.StringIO()
            )

        assert excinfo.value.code == 2

    def test_log_file_receives_json_events_even_without_a_console(
        self, environ: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Under pythonw (the logon task) there is no console: both standard streams are None.
        monkeypatch.setattr(sys, "stdout", None)
        monkeypatch.setattr(sys, "stderr", None)
        log_file = tmp_path / "data" / "logs" / "agent.log"

        code = agent_main.main(
            ["--duration", "0.2", "--log-file", str(log_file)],
            environ=environ,
            build=_synthetic_monitor,
        )

        assert code == 0
        events = [json.loads(line)["event"] for line in log_file.read_text("utf-8").splitlines()]
        assert events[:2] == ["config.loaded", "agent.started"]
        assert events[-1] == "agent.stopped"

    def test_a_second_instance_exits_with_code_3_without_starting_a_monitor(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        first = NamedMutexGuard(name=mutex_name(tmp_path / "data")).try_acquire()
        assert first is not None
        stderr = io.StringIO()

        def never_built(container: Container) -> Monitor:
            raise AssertionError("a duplicate agent must not build a monitor")

        try:
            code = agent_main.main(
                [], environ=environ, stdout=io.StringIO(), stderr=stderr, build=never_built
            )
        finally:
            first.release()

        assert code == agent_main.EXIT_ALREADY_RUNNING == 3
        assert _json_events(stderr)[-1] == "agent.already_running"

    def test_the_instance_lease_is_released_after_a_run(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        code = agent_main.main(
            ["--duration", "0.1"],
            environ=environ,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
            build=_synthetic_monitor,
        )
        assert code == 0

        lease = NamedMutexGuard(name=mutex_name(tmp_path / "data")).try_acquire()

        assert lease is not None
        lease.release()


def _synthetic_monitor(container: Container, cls: type[Monitor] = Monitor) -> Monitor:
    return cls(
        system_reader=FakeSystemReader(*(system() for _ in range(1000))),
        process_reader=FakeProcessReader(*(process_snapshot() for _ in range(1000))),
        clock=container.clock,
        evidence=RollingEvidence(
            EvidenceRetention(
                window=timedelta(minutes=1), max_system_samples=10, max_process_snapshots=10
            )
        ),
        intervals=SamplingIntervals(
            system_seconds=0.02, process_seconds=0.05, escalated_process_seconds=0.02
        ),
        thresholds=PressureThresholds(
            cpu_percent=90.0, memory_percent=90.0, memory_available_floor_bytes=0
        ),
        adaptive=AdaptivePolicy(escalation_max=timedelta(seconds=5), cooldown=timedelta(seconds=5)),
        own_pid=os.getpid(),
        health_log_interval_seconds=0.05,
    )


class _InterruptingMonitor(Monitor):
    async def run(self, stop: asyncio.Event) -> None:
        raise KeyboardInterrupt


def _interrupting_monitor(container: Container) -> Monitor:
    return _synthetic_monitor(container, cls=_InterruptingMonitor)


class TestMcpServer:
    def test_create_server_registers_the_v1_tools(self) -> None:
        server = mcp_server.create_server(fake_container())

        assert isinstance(server, MCPServer)
        assert server.name == "windows-medic"
        assert [t.name for t in anyio.run(server.list_tools)] == [
            *mcp_server.READ_TOOLS,
            *mcp_server.MUTATION_TOOLS,
        ]

    def test_module_exposes_server_object_for_mcp_dev(
        self,
        environ: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
        request: pytest.FixtureRequest,
    ) -> None:
        monkeypatch.setenv("WINDOWS_MEDIC_DATA_DIR", environ["WINDOWS_MEDIC_DATA_DIR"])
        composed: list[Container] = []

        def capturing(
            program: str, *, environ: Mapping[str, str], log_stream: TextIO, error_stream: TextIO
        ) -> Container | None:
            container = try_compose(
                program, environ=environ, log_stream=log_stream, error_stream=error_stream
            )
            if container is not None:
                composed.append(container)
            return container

        def close_all() -> None:
            for container in composed:
                container.close()

        monkeypatch.setattr(mcp_server, "try_compose", capturing)
        request.addfinalizer(close_all)

        server = mcp_server.server

        assert isinstance(server, MCPServer)
        assert len(anyio.run(server.list_tools)) == 8
        assert len(composed) == 1

    def test_mcp_dev_discovery_fails_loudly_on_bad_configuration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WINDOWS_MEDIC_LOG_LEVEL", "LOUD")

        with pytest.raises(RuntimeError, match="configuration error"):
            _ = mcp_server.server

    def test_module_has_no_other_dynamic_attributes(self) -> None:
        with pytest.raises(AttributeError):
            _ = mcp_server.nonexistent

    def test_version_flag(self, environ: dict[str, str]) -> None:
        stdout = io.StringIO()

        code = mcp_server.main(["--version"], environ=environ, stdout=stdout, stderr=io.StringIO())

        assert code == 0
        assert stdout.getvalue().strip() == f"windows-medic-mcp {windows_medic.__version__}"

    def test_main_serves_the_tools_over_the_injected_transport(
        self, environ: dict[str, str], capsys: pytest.CaptureFixture[str]
    ) -> None:
        served: list[MCPServer] = []
        stderr = io.StringIO()

        code = mcp_server.main(
            [], environ=environ, stdout=io.StringIO(), stderr=stderr, serve=served.append
        )

        assert code == 0
        assert [s.name for s in served] == ["windows-medic"]
        assert len(anyio.run(served[0].list_tools)) == 8
        assert _json_events(stderr) == ["config.loaded", "mcp.server.starting"]
        assert capsys.readouterr().out == "", "stdio transport: nothing may be written to stdout"

    def test_configuration_error_exits_with_code_2_without_serving(
        self, broken_environ: dict[str, str]
    ) -> None:
        served: list[MCPServer] = []
        stderr = io.StringIO()

        code = mcp_server.main(
            [], environ=broken_environ, stdout=io.StringIO(), stderr=stderr, serve=served.append
        )

        assert code == 2
        assert served == []
        assert "windows-medic-mcp: configuration error" in stderr.getvalue()
