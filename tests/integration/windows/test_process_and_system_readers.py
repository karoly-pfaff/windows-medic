"""Real process/system readers against the running Windows machine.

Only test-owned child processes are created; they are terminated through their own
``Popen`` handle (never by PID) after their identity has been validated.
"""

import ctypes
import os
import subprocess
import sys
from collections.abc import Iterator
from datetime import timedelta

import psutil
import pytest

from windows_medic.application.use_cases.get_system_health import (
    GetSystemHealth,
    HealthLimits,
)
from windows_medic.domain.models.metric import Unavailable, available
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.policies.rates import system_cpu_percent
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic.infrastructure.windows.nt_process_enumeration import enumerate_processes
from windows_medic.infrastructure.windows.psutil_system_reader import PsutilSystemReader
from windows_medic.infrastructure.windows.windows_process_reader import WindowsProcessReader

pytestmark = pytest.mark.windows_integration

SLEEPER = "import time; time.sleep(120)"
SPINNER = "while True: pass"

# In a uv/venv, sys.executable is a launcher that runs the real interpreter as a child.
# Spawning the base interpreter keeps the observed PID the one doing the work.
INTERPRETER = getattr(sys, "_base_executable", sys.executable)


def _spawn(program: str) -> Iterator[subprocess.Popen[bytes]]:
    child = subprocess.Popen([INTERPRETER, "-c", program])
    try:
        yield child
    finally:
        child.terminate()
        child.wait(timeout=30)


@pytest.fixture
def sleeper() -> Iterator[subprocess.Popen[bytes]]:
    yield from _spawn(SLEEPER)


@pytest.fixture
def spinner() -> Iterator[subprocess.Popen[bytes]]:
    yield from _spawn(SPINNER)


@pytest.fixture
def process_reader() -> WindowsProcessReader:
    return WindowsProcessReader(SystemClock())


@pytest.fixture
def system_reader() -> PsutilSystemReader:
    return PsutilSystemReader(SystemClock())


def _find(reader: WindowsProcessReader, pid: int) -> ProcessObservation:
    matches = [p for p in reader.snapshot().processes if p.identity.pid == pid]
    assert len(matches) == 1, f"expected exactly one observation for pid {pid}"
    return matches[0]


class TestProcessReader:
    def test_snapshot_includes_a_test_owned_child_with_readable_fields(
        self, sleeper: subprocess.Popen[bytes], process_reader: WindowsProcessReader
    ) -> None:
        observation = _find(process_reader, sleeper.pid)

        assert observation.identity.create_time.tzinfo is not None
        assert available(observation.name)
        assert observation.name.lower().startswith("python")
        assert available(observation.command_line)
        assert "time.sleep(120)" in " ".join(observation.command_line)
        assert observation.parent_pid == os.getpid()
        assert available(observation.cpu_time_seconds)
        assert available(observation.working_set_bytes)
        assert observation.working_set_bytes > 0
        assert available(observation.thread_count)
        assert available(observation.handle_count)

    def test_get_resolves_the_exact_identity_and_rejects_a_reused_pid(
        self, sleeper: subprocess.Popen[bytes], process_reader: WindowsProcessReader
    ) -> None:
        identity = _find(process_reader, sleeper.pid).identity

        resolved = process_reader.get(identity)
        stale = ProcessIdentity(identity.pid, identity.create_time + timedelta(seconds=1))

        assert resolved is not None
        assert resolved.identity == identity
        assert process_reader.get(stale) is None

    def test_get_returns_none_once_the_process_has_exited(
        self, process_reader: WindowsProcessReader
    ) -> None:
        child = subprocess.Popen([INTERPRETER, "-c", SLEEPER])
        try:
            identity = _find(process_reader, child.pid).identity
        finally:
            child.terminate()
            child.wait(timeout=30)

        assert process_reader.get(identity) is None

    def test_system_processes_are_identified_even_when_fields_are_denied(
        self, process_reader: WindowsProcessReader
    ) -> None:
        snapshot = process_reader.snapshot()

        [system] = [p for p in snapshot.processes if p.identity.pid == 4]
        assert system.name == "System"
        assert available(system.cpu_time_seconds)
        assert available(system.thread_count)
        assert isinstance(system.exe_path, Unavailable), "no fake empty path for System"
        assert isinstance(system.command_line, Unavailable)
        unavailable = [p for p in snapshot.processes if not available(p.exe_path)]
        assert unavailable, "at least one process should have no readable image path"

    def test_snapshot_is_large_and_never_raises(self, process_reader: WindowsProcessReader) -> None:
        snapshot = process_reader.snapshot()

        assert len(snapshot.processes) > 20
        assert snapshot.skipped_count >= 0
        assert len({p.identity for p in snapshot.processes}) == len(snapshot.processes)


class TestSystemReader:
    def test_snapshot_reports_plausible_machine_facts(
        self, system_reader: PsutilSystemReader
    ) -> None:
        observation = system_reader.snapshot()

        assert observation.cpu_count >= 1
        assert observation.memory.total_bytes > observation.memory.available_bytes > 0
        assert observation.process_count > 20
        assert available(observation.commit)
        assert 0 < observation.commit.used_bytes <= observation.commit.limit_bytes
        assert available(observation.disk_io)

    def test_two_snapshots_yield_a_bounded_cpu_percentage(
        self, system_reader: PsutilSystemReader
    ) -> None:
        before = system_reader.snapshot()
        SystemClock().sleep(0.25)
        after = system_reader.snapshot()

        percent = system_cpu_percent(before.cpu_times, after.cpu_times)

        assert available(percent)
        assert 0.0 <= percent <= 100.0


class TestGetSystemHealthEndToEnd:
    def test_a_cpu_bound_child_ranks_among_top_cpu_contributors(
        self,
        spinner: subprocess.Popen[bytes],
        process_reader: WindowsProcessReader,
        system_reader: PsutilSystemReader,
    ) -> None:
        use_case = GetSystemHealth(
            system_reader=system_reader,
            process_reader=process_reader,
            clock=SystemClock(),
            limits=HealthLimits(measurement_window_seconds=0.5, top_contributors=10),
        )

        health = use_case.execute()

        spinner_entries = [c for c in health.top_cpu if c.identity.pid == spinner.pid]
        assert len(spinner_entries) == 1, [c.identity.pid for c in health.top_cpu]
        assert available(spinner_entries[0].cpu_percent)
        assert spinner_entries[0].cpu_percent > 0.0
        assert available(health.cpu_percent)
        assert health.process_count > 20
        assert len(health.top_memory) == 10


class TestKernelEnumerationLayout:
    """The ctypes layout in nt_process_enumeration must agree with the live kernel."""

    def test_current_process_entry_matches_independent_sources(self) -> None:
        entries = enumerate_processes()
        [me] = [e for e in entries if e.pid == os.getpid()]
        session = ctypes.c_ulong()
        assert ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session))
        reference = psutil.Process()

        assert me.image_name.lower() == "python.exe"
        assert me.parent_pid == os.getppid()
        assert me.session_id == session.value
        assert abs(me.create_time.timestamp() - reference.create_time()) < 0.01
        assert me.thread_count >= 1
        assert me.handle_count > 0
        assert me.working_set_bytes > 0
        assert me.private_bytes > 0
        assert me.cpu_time_seconds >= 0.0

    def test_enumeration_is_fast_enough_for_a_monitor(self) -> None:
        clock = SystemClock()
        started = clock.now()

        for _ in range(5):
            entries = enumerate_processes()

        elapsed = (clock.now() - started).total_seconds()
        assert len(entries) > 20
        assert 0 not in {e.pid for e in entries}
        assert 4 in {e.pid for e in entries}
        assert elapsed < 2.0, f"5 enumerations took {elapsed:.2f}s"

    def test_full_snapshot_is_fast_enough_for_a_monitor(
        self, process_reader: WindowsProcessReader
    ) -> None:
        clock = SystemClock()
        started = clock.now()

        snapshot = process_reader.snapshot()

        elapsed = (clock.now() - started).total_seconds()
        assert len(snapshot.processes) > 20
        assert elapsed < 3.0, f"snapshot took {elapsed:.2f}s"
