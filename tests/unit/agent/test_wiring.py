"""build_monitor maps typed settings onto the monitor's policies."""

import io
import logging
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from windows_medic.domain.policies.adaptive_sampling import AdaptivePolicy, SamplingMode
from windows_medic.domain.policies.pressure import PressureThresholds
from windows_medic.domain.policies.pressure_lifecycle import LifecyclePolicy
from windows_medic_agent.monitor import SamplingIntervals
from windows_medic_agent.wiring import build_monitor
from windows_medic_root.container import compose


@pytest.fixture
def root_logger_state() -> Iterator[None]:
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def test_monitor_policies_come_from_settings(
    root_logger_state: None, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "[sampling]\nsystem_interval_seconds = 3\nprocess_interval_seconds = 12\n"
        "pressure_process_interval_seconds = 4\npressure_escalation_max_seconds = 120\n"
        "pressure_cooldown_seconds = 30\n"
        "[pressure]\ncpu_percent = 80\nmemory_percent = 85\nmemory_available_floor_mib = 1024\n",
        encoding="utf-8",
    )
    container = compose(
        environ={"WINDOWS_MEDIC_DATA_DIR": str(tmp_path), "WINDOWS_MEDIC_CONFIG_FILE": str(config)},
        log_stream=io.StringIO(),
    )
    request.addfinalizer(container.close)

    monitor = build_monitor(container)

    assert monitor.intervals == SamplingIntervals(
        system_seconds=3.0, process_seconds=12.0, escalated_process_seconds=4.0
    )
    assert monitor.thresholds == PressureThresholds(
        cpu_percent=80.0, memory_percent=85.0, memory_available_floor_bytes=1024 * 1024**2
    )
    assert monitor.adaptive == AdaptivePolicy(
        escalation_max=timedelta(seconds=120), cooldown=timedelta(seconds=30)
    )
    assert monitor.health().mode is SamplingMode.NORMAL
    assert monitor.health().system_sample_count == 0


def test_monitor_gets_an_incident_engine_from_settings(
    root_logger_state: None, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "[pressure]\ncpu_duration_seconds = 5\nmemory_duration_seconds = 7\n"
        "[incidents]\nrecovery_seconds = 3\nmax_contributors = 4\n",
        encoding="utf-8",
    )
    container = compose(
        environ={"WINDOWS_MEDIC_DATA_DIR": str(tmp_path), "WINDOWS_MEDIC_CONFIG_FILE": str(config)},
        log_stream=io.StringIO(),
    )
    request.addfinalizer(container.close)

    engine = build_monitor(container).incident_engine

    assert engine is not None
    assert engine.policy.cpu_lifecycle == LifecyclePolicy(
        duration=timedelta(seconds=5), recovery=timedelta(seconds=3)
    )
    assert engine.policy.memory_lifecycle.duration == timedelta(seconds=7)
    assert engine.policy.evidence.max_contributors == 4
    assert engine.policy.retention == timedelta(days=7)
