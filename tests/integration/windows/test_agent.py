"""The monitoring agent against the real machine, bounded in time and memory."""

import asyncio
import io
import json
import logging
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from windows_medic.domain.models.metric import available
from windows_medic_agent.wiring import build_monitor
from windows_medic_root.container import compose

pytestmark = pytest.mark.windows_integration

FAST_CONFIG = (
    "[sampling]\nsystem_interval_seconds = 0.2\nprocess_interval_seconds = 0.5\n"
    "pressure_process_interval_seconds = 0.2\n"
    "[history]\nmax_system_samples = 10\nmax_process_snapshots = 3\n"
    "[agent]\nhealth_log_interval_seconds = 1\n"
)


@pytest.fixture
def root_logger_state() -> Iterator[None]:
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


@pytest.fixture
def environ(tmp_path: Path) -> dict[str, str]:
    config = tmp_path / "config.toml"
    config.write_text(FAST_CONFIG, encoding="utf-8")
    return {
        **os.environ,
        "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data"),
        "WINDOWS_MEDIC_CONFIG_FILE": str(config),
    }


def test_monitor_samples_the_real_machine_within_bounds(
    root_logger_state: None, environ: dict[str, str], request: pytest.FixtureRequest
) -> None:
    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)
    monitor = build_monitor(container)

    async def run_for(seconds: float) -> None:
        stop = asyncio.Event()
        asyncio.get_running_loop().call_later(seconds, stop.set)
        await monitor.run(stop)

    asyncio.run(run_for(3.0))
    health = monitor.health()

    assert health.system_sample_count >= 8
    assert health.process_snapshot_count >= 3
    assert health.system_samples_held <= 10
    assert health.process_snapshots_held <= 3
    assert health.system_failures == 0
    assert health.process_failures == 0
    assert available(health.self_working_set_bytes)
    assert health.self_working_set_bytes > 0
    assert available(health.self_cpu_percent)
    assert health.max_process_sample_seconds < 3.0


def test_agent_console_script_runs_for_a_bounded_duration(environ: dict[str, str]) -> None:
    executable = Path(sys.executable).parent / "windows-medic-agent.exe"

    completed = subprocess.run(
        [str(executable), "--duration", "3"],
        capture_output=True,
        text=True,
        check=False,
        env=environ,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""
    records = [json.loads(line) for line in completed.stderr.splitlines()]
    events = [record["event"] for record in records]
    assert events[:2] == ["config.loaded", "agent.started"]
    assert events[-2:] == ["agent.monitor.stopped", "agent.stopped"]
    assert "agent.health" in events
    final = records[-2]
    assert final["system_sample_count"] >= 5
    assert final["process_snapshot_count"] >= 1
    assert final["system_failures"] == 0
    assert isinstance(final["self_working_set_bytes"], int)


INCIDENT_CONFIG = FAST_CONFIG + (
    "[pressure]\ncpu_percent = 0.5\ncpu_duration_seconds = 1\n"
    "[incidents]\nrecovery_seconds = 1\npersist_interval_seconds = 1\n"
)


SPIN_ONE_CORE = (
    "import time\nend = time.monotonic() + 30\nwhile time.monotonic() < end:\n    pass\n"
)


def test_lowered_thresholds_produce_a_real_incident_that_diagnose_explains(tmp_path: Path) -> None:
    """A test-owned busy loop keeps machine CPU above a 0.5 % threshold, so a real incident
    opens. One spinning core is several percent of any machine; an idle runner alone may
    dip below the threshold and never sustain it."""
    config = tmp_path / "config.toml"
    config.write_text(INCIDENT_CONFIG, encoding="utf-8")
    environ = {
        **os.environ,
        "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data"),
        "WINDOWS_MEDIC_CONFIG_FILE": str(config),
    }
    scripts = Path(sys.executable).parent

    spinner = subprocess.Popen([sys.executable, "-c", SPIN_ONE_CORE])  # self-terminating
    try:
        agent = subprocess.run(
            [str(scripts / "windows-medic-agent.exe"), "--duration", "5"],
            capture_output=True,
            text=True,
            check=False,
            env=environ,
            timeout=60,
        )
    finally:
        spinner.kill()  # our own child, through our own handle
        spinner.wait(timeout=30)
    assert agent.returncode == 0, agent.stderr
    events = [json.loads(line)["event"] for line in agent.stderr.splitlines()]
    assert "incident.opened" in events, events
    assert "incident.persist_failed" not in events

    listing = subprocess.run(
        [str(scripts / "windows-medic.exe"), "incidents"],
        capture_output=True,
        text=True,
        check=False,
        env=environ,
        timeout=60,
    )
    assert listing.returncode == 0, listing.stderr
    assert listing.stdout.startswith("Recent incidents: 1 (newest first)")
    assert "cpu_pressure" in listing.stdout
    assert (tmp_path / "data" / "incidents.sqlite3").is_file()

    diagnosis = subprocess.run(
        [str(scripts / "windows-medic.exe"), "diagnose", "--since-minutes", "5"],
        capture_output=True,
        text=True,
        check=False,
        env=environ,
        timeout=60,
    )
    assert diagnosis.returncode == 0, diagnosis.stderr
    assert diagnosis.stdout.startswith("Slowdown diagnosis: last 5 min")
    assert "Incidents in window: 1 (newest first)" in diagnosis.stdout
    assert "cpu_pressure [severity" in diagnosis.stdout
    assert "confidence raised by: sustained_incident" in diagnosis.stdout
