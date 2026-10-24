"""Installation and operations against the real machine: Task Scheduler, the named mutex,
the console scripts. Nothing here touches the user's own installation: the scheduler
test uses its own task name and every agent runs against a temporary data directory,
whose mutex name differs from the installed agent's.
"""

import contextlib
import json
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import psutil
import pytest

from windows_medic.application.ports.startup_registry import Registration
from windows_medic.infrastructure.windows.single_instance import NamedMutexGuard, mutex_name
from windows_medic.infrastructure.windows.task_scheduler import SchtasksStartupRegistry

pytestmark = pytest.mark.windows_integration

SCRIPTS = Path(sys.executable).parent
SCHTASKS = Path(os.environ["SYSTEMROOT"]) / "System32" / "schtasks.exe"
FAST_CONFIG = (
    "[sampling]\nsystem_interval_seconds = 0.2\nprocess_interval_seconds = 0.5\n"
    "pressure_process_interval_seconds = 0.2\n"
    "[history]\nmax_system_samples = 10\nmax_process_snapshots = 3\n"
    "[agent]\nhealth_log_interval_seconds = 1\n"
)
STARTUP_DEADLINE_SECONDS = 20.0


@pytest.fixture
def environ(tmp_path: Path) -> dict[str, str]:
    config = tmp_path / "config.toml"
    config.write_text(FAST_CONFIG, encoding="utf-8")
    return {
        **os.environ,
        "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data"),
        "WINDOWS_MEDIC_CONFIG_FILE": str(config),
    }


def run_cli(*arguments: str, environ: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPTS / "windows-medic.exe"), *arguments],
        capture_output=True,
        text=True,
        check=False,
        env=environ,
        timeout=120,
    )


def kill_tree(popen: subprocess.Popen[str] | subprocess.Popen[bytes]) -> None:
    """Kill a console-script launcher *and* the interpreter it spawned.

    uv's launchers (``python.exe`` in the venv, every console script) run the real
    interpreter as a child; killing the launcher alone would orphan it.
    """
    try:
        members = [psutil.Process(popen.pid), *psutil.Process(popen.pid).children(recursive=True)]
    except psutil.NoSuchProcess:
        members = []
    for member in members:
        with contextlib.suppress(psutil.NoSuchProcess):
            member.kill()
    popen.wait(timeout=30)
    psutil.wait_procs(members, timeout=30)


def wait_until(condition: Callable[[], bool], *, deadline_seconds: float) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return False


class TestTaskScheduler:
    @pytest.fixture
    def registry(self) -> Iterator[SchtasksStartupRegistry]:
        user = f"{os.environ['USERDOMAIN']}\\{os.environ['USERNAME']}"
        registry = SchtasksStartupRegistry(
            schtasks=SCHTASKS, user=user, task_name=f"WindowsMedic\\Test-{uuid.uuid4().hex}"
        )
        yield registry
        registry.unregister()  # guaranteed cleanup; False when the test removed it

    def test_register_query_run_and_unregister_a_least_privilege_logon_task(
        self, registry: SchtasksStartupRegistry, tmp_path: Path
    ) -> None:
        marker = tmp_path / "ran.txt"
        pythonw = SCRIPTS / "pythonw.exe"
        interpreter = pythonw if pythonw.exists() else Path(sys.executable)
        command = [
            str(interpreter),
            "-c",
            f"open({str(marker)!r}, 'w').write('ran')",
        ]
        assert registry.state().registration is Registration.NOT_REGISTERED

        registry.register(command)
        state = registry.state()

        assert state.registration is Registration.REGISTERED
        assert state.command is not None
        assert state.command.startswith(str(interpreter))
        assert "ran" in state.command

        registry.run_now()

        assert wait_until(marker.exists, deadline_seconds=STARTUP_DEADLINE_SECONDS), (
            "the scheduled command did not run"
        )
        assert registry.unregister() is True
        assert registry.state().registration is Registration.NOT_REGISTERED
        assert registry.unregister() is False


class TestSingleInstance:
    def test_the_mutex_is_held_by_a_process_and_freed_when_it_exits(self, tmp_path: Path) -> None:
        name = mutex_name(tmp_path)
        # Holds the mutex until its stdin closes, then exits normally (the kernel closes
        # the handle either way; a clean exit keeps the test free of orphaned children).
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import ctypes, sys\n"
                    "kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)\n"
                    f"handle = kernel32.CreateMutexW(None, True, {name!r})\n"
                    "assert handle and ctypes.get_last_error() == 0\n"
                    "print('held', flush=True)\n"
                    "sys.stdin.readline()\n"
                ),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert holder.stdout is not None
            assert holder.stdout.readline().strip() == "held"

            assert NamedMutexGuard(name=name).try_acquire() is None
        finally:
            holder.communicate(input="release\n", timeout=30)
            if holder.returncode != 0:
                kill_tree(holder)

        assert holder.returncode == 0
        lease = NamedMutexGuard(name=name).try_acquire()

        assert lease is not None
        lease.release()

    def test_a_second_agent_for_the_same_data_directory_exits_with_code_3(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        log_file = tmp_path / "data" / "logs" / "first.log"
        first = subprocess.Popen(
            [
                str(SCRIPTS / "windows-medic-agent.exe"),
                "--duration",
                "30",
                "--log-file",
                str(log_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environ,
        )
        try:
            assert wait_until(
                lambda: log_file.exists() and "agent.started" in log_file.read_text("utf-8"),
                deadline_seconds=STARTUP_DEADLINE_SECONDS,
            ), "the first agent did not start"

            second = subprocess.run(
                [str(SCRIPTS / "windows-medic-agent.exe"), "--duration", "30"],
                capture_output=True,
                text=True,
                check=False,
                env=environ,
                timeout=60,
            )
        finally:
            kill_tree(first)

        assert second.returncode == 3, second.stderr
        events = [json.loads(line)["event"] for line in second.stderr.splitlines()]
        assert events[-1] == "agent.already_running"
        assert "agent.started" not in events


class TestConsoleScripts:
    def test_windowless_agent_writes_a_json_log_file(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        log_file = tmp_path / "data" / "logs" / "windows-medic-agent.log"

        completed = subprocess.run(
            [
                str(SCRIPTS / "windows-medic-agentw.exe"),
                "--duration",
                "2",
                "--log-file",
                str(log_file),
            ],
            capture_output=True,
            text=True,
            check=False,
            env=environ,
            timeout=60,
        )

        assert completed.returncode == 0
        records = [json.loads(line) for line in log_file.read_text("utf-8").splitlines()]
        events = [record["event"] for record in records]
        assert events[:2] == ["config.loaded", "agent.started"]
        assert events[-1] == "agent.stopped"
        assert all(isinstance(record["ts"], str) for record in records)

    def test_doctor_status_and_config_against_a_fresh_data_directory(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        data_dir = tmp_path / "data"
        environ = {k: v for k, v in environ.items() if k != "WINDOWS_MEDIC_CONFIG_FILE"}

        doctor = run_cli("doctor", environ=environ)
        status = run_cli("status", environ=environ)
        overview = run_cli(environ=environ)
        init = run_cli("config", "init", environ=environ)
        again = run_cli("config", "init", environ=environ)
        check = run_cli("config", "check", environ=environ)
        mcp = run_cli("mcp-config", environ=environ)

        assert doctor.returncode == 0, doctor.stdout + doctor.stderr
        assert "[ok] runtime:" in doctor.stdout
        assert "[ok] data_directory:" in doctor.stdout
        assert "[ok] database:" in doctor.stdout
        assert "[ok] executables:" in doctor.stdout
        assert "[warning] startup:" in doctor.stdout or "[ok] startup:" in doctor.stdout
        assert "[warning] agent:" in doctor.stdout
        assert status.returncode == 0, status.stderr
        assert f"Data directory:  {data_dir}" in status.stdout
        assert f"Agent log:       {data_dir / 'logs' / 'windows-medic-agent.log'}" in status.stdout
        assert "Agent:           not running" in status.stdout
        assert overview.returncode == 0
        assert "Commands: health" in overview.stdout
        assert init.returncode == 0, init.stderr
        assert (data_dir / "config.toml").read_text("utf-8").startswith("# Windows Medic")
        assert again.returncode == 1
        assert "already exists" in again.stderr
        assert check.returncode == 0, check.stderr
        assert f"Configuration: {data_dir / 'config.toml'} (loaded)" in check.stdout
        assert "\n[pressure]\n" in check.stdout
        assert mcp.returncode == 0
        snippet = json.loads(mcp.stdout.partition("\n\n")[2])
        assert snippet["mcpServers"]["windows-medic"]["command"] == str(
            SCRIPTS / "windows-medic-mcp.exe"
        )
        assert Path(snippet["mcpServers"]["windows-medic"]["command"]).is_file()
