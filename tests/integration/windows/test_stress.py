"""Failure hardening against the real machine: pressure transitions, churn, races.

Every scenario is bounded and test-owned: load comes from children that self-terminate,
memory is committed in one child sized against what the machine can spare, the agent runs
in-process against a temporary data directory, and thresholds are lowered so a real
transition happens without harming the machine.
"""

import asyncio
import io
import json
import logging
import os
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import psutil
import pytest

from tests.soak.harness import agent_executable
from tests.soak.stress import INTERPRETER, ProcessChurn, cpu_burn, memory_hold, wait_until
from windows_medic.domain.models.incident import IncidentKind, IncidentStatus
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.infrastructure.persistence.sqlite_connection import open_database
from windows_medic_agent.monitor import AgentHealth
from windows_medic_agent.wiring import build_monitor
from windows_medic_root.container import Container, compose

pytestmark = pytest.mark.windows_integration

MIB = 1024 * 1024
GIB = 1024 * MIB
FAST_SAMPLING = (
    "[sampling]\nsystem_interval_seconds = 0.2\nprocess_interval_seconds = 0.5\n"
    "pressure_process_interval_seconds = 0.2\n"
    "[history]\nmax_system_samples = 200\nmax_process_snapshots = 10\n"
    "[incidents]\nrecovery_seconds = 1\npersist_interval_seconds = 1\n"
    "[agent]\nhealth_log_interval_seconds = 1\n"
)
BUSY_MACHINE_CPU_PERCENT = 55.0


@pytest.fixture
def root_logger_state() -> Iterator[None]:
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def _environ(tmp_path: Path, config: str) -> dict[str, str]:
    config_file = tmp_path / "config.toml"
    config_file.write_text(config, encoding="utf-8")
    return {
        **os.environ,
        "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data"),
        "WINDOWS_MEDIC_CONFIG_FILE": str(config_file),
    }


class MonitorRun:
    """The in-process agent under an asyncio loop, driven from the test thread."""

    def __init__(self, container: Container, log: io.StringIO) -> None:
        self.container = container
        self.log = log
        self.monitor = build_monitor(container)

    async def run_for(self, seconds: float) -> None:
        stop = asyncio.Event()
        asyncio.get_running_loop().call_later(seconds, stop.set)
        await self.monitor.run(stop)

    def events(self) -> list[dict[str, object]]:
        records = [json.loads(line) for line in self.log.getvalue().splitlines()]
        return [r for r in records if isinstance(r, dict)]

    def health(self) -> AgentHealth:
        return self.monitor.health()


def _run_monitor(container: Container, log: io.StringIO, seconds: float) -> MonitorRun:
    run = MonitorRun(container, log)
    asyncio.run(run.run_for(seconds))
    return run


def _assert_loop_survived(run: MonitorRun) -> None:
    health = run.health()
    assert health.system_failures == 0, run.log.getvalue()[-4000:]
    assert health.process_failures == 0, run.log.getvalue()[-4000:]
    assert health.incident_persist_failures == 0
    assert "collector.crashed" not in {e["event"] for e in run.events()}


class TestCpuPressureTransitions:
    def test_repeated_bursts_open_bounded_incidents_that_all_close(
        self, root_logger_state: None, tmp_path: Path, request: pytest.FixtureRequest
    ) -> None:
        baseline = psutil.cpu_percent(interval=1.0)
        if baseline > BUSY_MACHINE_CPU_PERCENT:
            pytest.skip(f"machine already at {baseline:.0f} % CPU; no clean transition possible")
        threshold = baseline + (100.0 - baseline) / 2
        config = FAST_SAMPLING + (
            f"[pressure]\ncpu_percent = {threshold:.1f}\ncpu_duration_seconds = 1\n"
            "memory_percent = 100\nmemory_available_floor_mib = 0\n"
        )
        log = io.StringIO()
        container = compose(environ=_environ(tmp_path, config), log_stream=log)
        request.addfinalizer(container.close)
        workers = psutil.cpu_count(logical=True) or 2
        cycles = 3

        async def scenario() -> None:
            await asyncio.sleep(1.0)
            for _ in range(cycles):
                with cpu_burn(workers=workers, seconds=3.5):
                    await asyncio.sleep(3.0)
                await asyncio.sleep(3.5)

        run = MonitorRun(container, log)

        async def drive() -> None:
            stop = asyncio.Event()
            monitor_task = asyncio.create_task(run.monitor.run(stop))
            await scenario()
            await asyncio.sleep(2.0)
            stop.set()
            await monitor_task

        asyncio.run(drive())

        _assert_loop_survived(run)
        health = run.health()
        assert 1 <= health.incidents_opened <= cycles, run.events()
        assert health.incidents_live == 0
        incidents = container.list_recent_incidents.execute(limit=10)
        assert len(incidents) == health.incidents_opened
        assert all(i.kind is IncidentKind.CPU_PRESSURE for i in incidents)
        assert all(i.status is IncidentStatus.CLOSED for i in incidents)
        events = [e["event"] for e in run.events()]
        assert events.count("incident.opened") == health.incidents_opened
        assert events.count("incident.closed") == health.incidents_opened


class TestMemoryPressure:
    def test_a_bounded_allocation_opens_one_incident_that_recovers(
        self, root_logger_state: None, tmp_path: Path, request: pytest.FixtureRequest
    ) -> None:
        # The floor sits half an allocation below the quietest recent reading, so only our
        # allocation crosses it; background fluctuations of up to that margin do not.
        memory = psutil.virtual_memory()
        allocation = min(2 * GIB, memory.total // 8)
        available = min(psutil.virtual_memory().available for _ in range(5))
        if available - allocation < 2 * GIB:
            pytest.skip("less than 2 GiB would remain available; not allocating")
        floor_mib = (available - allocation // 2) // MIB
        config = FAST_SAMPLING + (
            "[pressure]\ncpu_percent = 100\ncpu_duration_seconds = 1\n"
            f"memory_percent = 100\nmemory_available_floor_mib = {floor_mib}\n"
            "memory_duration_seconds = 1\n"
        )
        log = io.StringIO()
        container = compose(environ=_environ(tmp_path, config), log_stream=log)
        request.addfinalizer(container.close)
        run = MonitorRun(container, log)

        async def drive() -> None:
            stop = asyncio.Event()
            monitor_task = asyncio.create_task(run.monitor.run(stop))
            await asyncio.sleep(1.5)
            with memory_hold(size_bytes=allocation, seconds=30):
                await asyncio.sleep(4.0)
            deadline = asyncio.get_running_loop().time() + 8.0
            while run.health().incidents_live and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.2)
            stop.set()
            await monitor_task

        asyncio.run(drive())

        _assert_loop_survived(run)
        health = run.health()
        assert health.incidents_opened == 1, run.events()
        assert health.incidents_live == 0
        [incident] = container.list_recent_incidents.execute(limit=10)
        assert incident.kind is IncidentKind.MEMORY_PRESSURE
        assert incident.status is IncidentStatus.CLOSED


class TestProcessChurn:
    def test_the_monitor_loop_survives_rapid_process_churn(
        self, root_logger_state: None, tmp_path: Path, request: pytest.FixtureRequest
    ) -> None:
        config = FAST_SAMPLING + (
            "[pressure]\ncpu_percent = 100\nmemory_percent = 100\nmemory_available_floor_mib = 0\n"
        )
        log = io.StringIO()
        container = compose(environ=_environ(tmp_path, config), log_stream=log)
        request.addfinalizer(container.close)

        with ProcessChurn(batch=6, pause_seconds=0.05) as churn:
            # Long enough for 100+ processes even when the machine is busy (~10/s).
            run = _run_monitor(container, log, seconds=20.0)
        spawned = churn.counter.spawned

        assert spawned >= 100, spawned
        _assert_loop_survived(run)
        health = run.health()
        assert health.process_snapshot_count >= 8
        assert health.system_sample_count >= 30
        assert health.max_process_sample_seconds < 5.0


class TestPortOwnerChurn:
    LISTENER = (
        "import socket, sys, time\n"
        "s = socket.socket()\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)\n"
        "s.bind(('127.0.0.1', int(sys.argv[1])))\n"
        "s.listen()\n"
        "print('listening', flush=True)\n"
        "time.sleep(60)\n"
    )

    def _identity(self, container: Container, pid: int) -> ProcessIdentity:
        found = [o for o in container.process_reader.snapshot().processes if o.identity.pid == pid]
        assert len(found) == 1
        return found[0].identity

    def test_inspect_port_never_reports_a_foreign_or_stale_identity(
        self, root_logger_state: None, tmp_path: Path, request: pytest.FixtureRequest
    ) -> None:
        container = compose(environ=_environ(tmp_path, ""), log_stream=io.StringIO())
        request.addfinalizer(container.close)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        seen: set[ProcessIdentity] = set()
        resolved = 0
        cycles = 10

        for _ in range(cycles):
            child = subprocess.Popen(
                [INTERPRETER, "-c", self.LISTENER, str(port)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            try:
                assert child.stdout is not None
                assert child.stdout.readline().strip() == "listening"
                current = self._identity(container, child.pid)
                assert current not in seen
                seen.add(current)
                for _ in range(3):
                    inspection = container.inspect_port.execute(port)
                    for owner in inspection.owners:
                        assert owner.identity == current, (owner.identity, current)
                        resolved += 1
                    for unresolved in inspection.unresolved:
                        assert unresolved.reported_pid in (None, child.pid)
            finally:
                child.kill()
                child.wait(timeout=30)
                if child.stdout is not None:
                    child.stdout.close()
            after = container.inspect_port.execute(port)
            assert all(owner.identity != current for owner in after.owners)
            assert wait_until(
                lambda: not container.inspect_port.execute(port).owners, deadline_seconds=5
            )

        assert len(seen) == cycles
        assert resolved >= cycles, "the live listener was never resolved to its exact identity"


class TestPersistence:
    def test_history_survives_an_agent_killed_mid_write(
        self, root_logger_state: None, tmp_path: Path
    ) -> None:
        """A WAL database written by an agent that dies without closing stays consistent."""
        config = FAST_SAMPLING + (
            "[pressure]\ncpu_percent = 0.5\ncpu_duration_seconds = 0.5\n"
            "memory_percent = 100\nmemory_available_floor_mib = 0\n"
        )
        environ = _environ(tmp_path, config)
        data_dir = tmp_path / "data"
        log_file = data_dir / "logs" / "agent.log"
        agent = subprocess.Popen(
            [str(agent_executable()), "--duration", "60", "--log-file", str(log_file)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environ,
        )
        try:
            assert wait_until(
                lambda: log_file.exists() and "incident.opened" in log_file.read_text("utf-8"),
                deadline_seconds=30,
            ), "no incident opened from baseline activity"
            time.sleep(1.5)  # let at least one paced persist happen after the open
        finally:
            launcher = psutil.Process(agent.pid)
            members = [launcher, *launcher.children(recursive=True)]
            for member in members:
                try:
                    member.kill()
                except psutil.NoSuchProcess:
                    continue
            # TerminateProcess returns before the process is gone; until every member has
            # exited, the killed interpreter may still hold the database files open.
            _, alive = psutil.wait_procs(members, timeout=30)
            assert alive == [], f"killed agent processes still running: {alive}"
            agent.wait(timeout=30)

        database = open_database(data_dir / "incidents.sqlite3")
        try:
            [(integrity,)] = database.connection.execute("PRAGMA integrity_check").fetchall()
            [(count,)] = database.connection.execute("SELECT COUNT(*) FROM incidents").fetchall()
        finally:
            database.close()

        assert integrity == "ok"
        assert count >= 1
        reopened = compose(environ=environ, log_stream=io.StringIO())
        try:
            summaries = reopened.list_recent_incidents.execute(limit=5)
        finally:
            reopened.close()
        assert summaries
        assert summaries[0].kind is IncidentKind.CPU_PRESSURE

    def test_a_hostile_writer_only_delays_incident_persistence(
        self, root_logger_state: None, tmp_path: Path, request: pytest.FixtureRequest
    ) -> None:
        """Another connection holding write locks intermittently: bounded retries, no loss."""
        config = FAST_SAMPLING + (
            "[pressure]\ncpu_percent = 0.5\ncpu_duration_seconds = 0.5\n"
            "memory_percent = 100\nmemory_available_floor_mib = 0\n"
        )
        log = io.StringIO()
        container = compose(environ=_environ(tmp_path, config), log_stream=log)
        request.addfinalizer(container.close)
        blocker = open_database(tmp_path / "data" / "incidents.sqlite3", busy_timeout_ms=10)
        stop = asyncio.Event()

        async def hold_locks_intermittently() -> None:
            while not stop.is_set():
                blocker.connection.execute("BEGIN IMMEDIATE")
                await asyncio.sleep(0.15)
                blocker.connection.execute("ROLLBACK")
                await asyncio.sleep(0.05)

        run = MonitorRun(container, log)

        async def drive() -> None:
            monitor_task = asyncio.create_task(run.monitor.run(stop))
            locker = asyncio.create_task(hold_locks_intermittently())
            await asyncio.sleep(6.0)
            stop.set()
            await monitor_task
            await locker

        try:
            asyncio.run(drive())
        finally:
            blocker.close()

        health = run.health()
        assert health.system_failures == 0
        assert health.incidents_opened >= 1
        assert health.incident_persist_failures <= 20  # bounded, not a crash
        events = [e["event"] for e in run.events()]
        assert "collector.crashed" not in events
        summaries = container.list_recent_incidents.execute(limit=5)
        assert len(summaries) >= 1, "the incident never made it to the store"
