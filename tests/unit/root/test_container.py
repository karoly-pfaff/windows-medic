"""Composition root: loads settings once, configures logging, returns typed wiring."""

import io
import json
import logging
import os
import sys
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest

import windows_medic
from tests.fakes import FakeStartupRegistry
from windows_medic.application.use_cases.clear_port import ClearPort
from windows_medic.application.use_cases.diagnose_slowdown import DiagnoseSlowdown
from windows_medic.application.use_cases.doctor import RunDoctor
from windows_medic.application.use_cases.get_system_health import GetSystemHealth, HealthLimits
from windows_medic.application.use_cases.init_config import InitConfig
from windows_medic.application.use_cases.inspect_port import InspectPort
from windows_medic.application.use_cases.inspect_process import InspectionLimits, InspectProcess
from windows_medic.application.use_cases.install_agent import InstallAgent, UninstallAgent
from windows_medic.application.use_cases.list_recent_incidents import ListRecentIncidents
from windows_medic.application.use_cases.list_recent_repairs import ListRecentRepairs
from windows_medic.application.use_cases.restart_windows_component import (
    RestartWindowsComponent,
)
from windows_medic.application.use_cases.show_status import ShowStatus
from windows_medic.application.use_cases.terminate_process import TerminateProcess
from windows_medic.infrastructure.config.settings import ConfigurationError, LogLevel
from windows_medic.infrastructure.filesystem.local_workspace import LocalWorkspace
from windows_medic.infrastructure.persistence.sqlite_incident_repository import (
    SqliteIncidentRepository,
)
from windows_medic.infrastructure.persistence.sqlite_repair_audit import (
    SqliteRepairAuditRepository,
)
from windows_medic.infrastructure.windows.component_controller import (
    WindowsComponentController,
)
from windows_medic.infrastructure.windows.elevation_launcher import UacElevationLauncher
from windows_medic.infrastructure.windows.hung_window_reader import Win32HungWindowReader
from windows_medic.infrastructure.windows.process_controller import WindowsProcessController
from windows_medic.infrastructure.windows.psutil_network_reader import PsutilNetworkReader
from windows_medic.infrastructure.windows.single_instance import NamedMutexGuard
from windows_medic.infrastructure.windows.task_scheduler import SchtasksStartupRegistry
from windows_medic_root import container as container_module
from windows_medic_root.container import (
    INCIDENT_DB_NAME,
    Container,
    compose,
    try_compose,
    utf8_text,
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
    return {"WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data")}


def _events(stream: io.StringIO) -> list[dict[str, object]]:
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert all(isinstance(record, dict) for record in records)
    return records


def test_compose_returns_validated_settings(
    root_logger_state: None,
    environ: dict[str, str],
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert isinstance(container, Container)
    assert container.settings.data_dir == tmp_path / "data"
    assert container.settings.logging.level is LogLevel.INFO


def test_compose_configures_structured_logging_at_the_configured_level(
    root_logger_state: None, environ: dict[str, str], request: pytest.FixtureRequest
) -> None:
    environ["WINDOWS_MEDIC_LOG_LEVEL"] = "ERROR"
    stream = io.StringIO()

    request.addfinalizer(compose(environ=environ, log_stream=stream).close)
    logging.getLogger("windows_medic.probe").warning("dropped")
    logging.getLogger("windows_medic.probe").error("kept")

    assert [record["event"] for record in _events(stream)] == ["kept"]


def test_compose_logs_where_configuration_came_from(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    stream = io.StringIO()

    request.addfinalizer(compose(environ=environ, log_stream=stream).close)

    loaded = [record for record in _events(stream) if record["event"] == "config.loaded"]
    assert len(loaded) == 1
    assert loaded[0]["data_dir"] == str(tmp_path / "data")
    assert loaded[0]["config_file"] is None


def test_compose_fails_fast_on_invalid_configuration(
    root_logger_state: None, environ: dict[str, str], request: pytest.FixtureRequest
) -> None:
    environ["WINDOWS_MEDIC_LOG_LEVEL"] = "LOUD"

    with pytest.raises(ConfigurationError, match=r"logging\.level"):
        compose(environ=environ, log_stream=io.StringIO())


def test_try_compose_returns_container_on_success(
    root_logger_state: None, environ: dict[str, str], request: pytest.FixtureRequest
) -> None:
    errors = io.StringIO()

    container = try_compose("prog", environ=environ, log_stream=io.StringIO(), error_stream=errors)

    assert isinstance(container, Container)
    request.addfinalizer(container.close)
    assert errors.getvalue() == ""


def test_try_compose_reports_configuration_errors_for_the_program(
    root_logger_state: None, environ: dict[str, str], request: pytest.FixtureRequest
) -> None:
    environ["WINDOWS_MEDIC_LOG_LEVEL"] = "LOUD"
    errors = io.StringIO()

    container = try_compose("prog", environ=environ, log_stream=io.StringIO(), error_stream=errors)

    assert container is None
    assert errors.getvalue().startswith("prog: configuration error")
    assert "logging.level" in errors.getvalue()


def test_output_streams_become_utf8_and_escape_what_utf8_cannot_carry() -> None:
    raw = io.BytesIO()
    redirected = io.TextIOWrapper(raw, encoding="cp1250", errors="strict", newline="")

    stream = utf8_text(redirected)
    stream.write("✳ claude \udc80\n")  # a lone surrogate, as Windows names may contain
    stream.flush()

    assert stream is redirected
    assert raw.getvalue() == "✳ claude \\udc80\n".encode()


def test_streams_without_an_encoding_are_left_alone() -> None:
    buffer = io.StringIO()

    assert utf8_text(buffer) is buffer


def test_purge_deletes_the_data_directory_while_the_container_holds_the_database(
    root_logger_state: None,
    environ: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    # Everything is real except Task Scheduler, so the user's own logon task is untouched.
    monkeypatch.setattr(
        container_module, "SchtasksStartupRegistry", lambda **_: FakeStartupRegistry()
    )
    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)
    assert (tmp_path / "data" / INCIDENT_DB_NAME).exists()

    report = container.uninstall_agent.execute(stop=False, purge_data=True)

    assert report.purged is True
    assert not (tmp_path / "data").exists()


def test_try_compose_reports_an_unopenable_database_and_logs_it(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / INCIDENT_DB_NAME).write_bytes(b"not a database" * 100)
    errors, logs = io.StringIO(), io.StringIO()

    container = try_compose("prog", environ=environ, log_stream=logs, error_stream=errors)

    assert container is None
    assert errors.getvalue().startswith("prog: storage error")
    assert INCIDENT_DB_NAME in errors.getvalue()
    assert [r["event"] for r in _events(logs) if r["level"] == "ERROR"] == ["storage.unavailable"]


def test_compose_wires_get_system_health_from_settings(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "[health]\nmeasurement_window_seconds = 0.25\ntop_contributors = 7\n", encoding="utf-8"
    )
    environ["WINDOWS_MEDIC_CONFIG_FILE"] = str(config)

    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert isinstance(container.get_system_health, GetSystemHealth)
    assert container.get_system_health.limits == HealthLimits(
        measurement_window_seconds=0.25, top_contributors=7
    )


def test_compose_wires_inspect_process_with_self_aware_protection(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "windows_directory = 'D:\\Win'\n"
        "[protection]\nadditional_protected_names = ['backup-agent.exe']\n"
        "[classifiers]\nclaude_markers = ['claude', 'anthropic']\n"
        "[inspection]\nmax_ancestors = 3\nmax_descendants = 4\n",
        encoding="utf-8",
    )
    environ["WINDOWS_MEDIC_CONFIG_FILE"] = str(config)

    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert isinstance(container.inspect_process, InspectProcess)
    assert container.protection_policy.own_pid == os.getpid()
    assert container.protection_policy.user_protected_names == ("backup-agent.exe",)
    assert container.protection_policy.windows_directory == "D:\\Win"
    assert "windows-medic" in container.protection_policy.windows_medic_markers
    assert container.ancestry_policy.claude_markers == ("claude", "anthropic")
    assert container.inspect_process.limits == InspectionLimits(max_ancestors=3, max_descendants=4)


def test_compose_wires_inspect_port_with_the_same_policies(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    config = tmp_path / "config.toml"
    config.write_text("[inspection]\nmax_port_owners = 2\n", encoding="utf-8")
    environ["WINDOWS_MEDIC_CONFIG_FILE"] = str(config)

    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert isinstance(container.inspect_port, InspectPort)
    assert isinstance(container.network_reader, PsutilNetworkReader)
    assert container.inspect_port.limits.max_port_owners == 2
    assert container.inspect_port.limits == container.inspect_process.limits


def test_compose_opens_the_incident_store_under_the_data_dir(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert isinstance(container.incident_repository, SqliteIncidentRepository)
    assert isinstance(container.list_recent_incidents, ListRecentIncidents)
    assert (tmp_path / "data" / INCIDENT_DB_NAME).is_file()
    assert container.list_recent_incidents.execute() == ()


def test_compose_wires_diagnose_slowdown_from_settings(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "[diagnosis]\ndefault_lookback_minutes = 15\nmax_lookback_minutes = 60\n"
        "max_findings = 4\nhog_cpu_percent = 12.5\nstale_process_age_minutes = 45\n"
        "max_hung_windows = 3\n"
        "[classifiers]\ndevelopment_command_markers = ['vite']\n"
        "[health]\nmeasurement_window_seconds = 0.25\n",
        encoding="utf-8",
    )
    environ["WINDOWS_MEDIC_CONFIG_FILE"] = str(config)

    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert isinstance(container.diagnose_slowdown, DiagnoseSlowdown)
    assert isinstance(container.hung_window_reader, Win32HungWindowReader)
    limits = container.diagnose_slowdown.limits
    assert limits.default_lookback == timedelta(minutes=15)
    assert limits.max_lookback == timedelta(minutes=60)
    assert limits.max_findings == 4
    assert limits.measurement == container.get_system_health.limits
    policy = container.diagnose_slowdown.policy
    assert policy.hogs.cpu_percent == 12.5
    assert policy.stale_after == timedelta(minutes=45)
    assert policy.classifier.command_markers == ("vite",)
    assert "node.exe" in policy.classifier.process_names
    assert policy.protection is container.protection_policy
    assert policy.ancestry is container.ancestry_policy
    assert policy.pressure.cpu_percent == 90.0


def test_compose_wires_the_repair_engine_from_settings(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "[repairs]\nverify_timeout_seconds = 2.5\nmax_tree_members = 20\n"
        "audit_retention_days = 3\nmax_audit_list = 7\n",
        encoding="utf-8",
    )
    environ["WINDOWS_MEDIC_CONFIG_FILE"] = str(config)

    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert isinstance(container.process_controller, WindowsProcessController)
    assert isinstance(container.repair_audit, SqliteRepairAuditRepository)
    assert isinstance(container.terminate_process, TerminateProcess)
    assert isinstance(container.clear_port, ClearPort)
    assert isinstance(container.list_recent_repairs, ListRecentRepairs)
    assert container.list_recent_repairs.execute() == ()
    limits = container.clear_port.executor.limits
    assert limits.verify_timeout == timedelta(seconds=2.5)
    assert limits.max_tree_members == 20
    assert container.terminate_process.executor is container.clear_port.executor


def test_compose_wires_component_recovery_with_the_high_risk_gate(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "[repairs]\nhigh_risk_repairs_enabled = true\ncomponent_verify_timeout_seconds = 3\n"
        "explorer_auto_restart_wait_seconds = 1\n",
        encoding="utf-8",
    )
    environ["WINDOWS_MEDIC_CONFIG_FILE"] = str(config)

    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert isinstance(container.restart_windows_component, RestartWindowsComponent)
    assert isinstance(container.component_controller, WindowsComponentController)
    assert isinstance(container.elevated_helper, UacElevationLauncher)
    assert container.restart_windows_component.high_risk_enabled is True
    limits = container.restart_windows_component.limits
    assert limits.verify_timeout == timedelta(seconds=3)
    assert limits.auto_restart_wait == timedelta(seconds=1)


def test_high_risk_repairs_are_disabled_by_default(
    root_logger_state: None, environ: dict[str, str], request: pytest.FixtureRequest
) -> None:
    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert container.restart_windows_component.high_risk_enabled is False


def test_compose_wires_the_operational_use_cases_and_locations(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    environ["USERDOMAIN"], environ["USERNAME"] = "DESKTOP", "dev"
    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    locations = container.locations
    assert locations.data_dir == tmp_path / "data"
    assert locations.config_file == tmp_path / "data" / "config.toml"
    assert locations.config_present is False
    assert locations.database == tmp_path / "data" / INCIDENT_DB_NAME
    assert locations.log_file == tmp_path / "data" / "logs" / "windows-medic-agent.log"
    assert locations.elevated_dir == tmp_path / "data" / "elevated"
    scripts = Path(sys.executable).parent
    assert container.executables.cli == scripts / "windows-medic.exe"
    assert container.executables.agent_gui == scripts / "windows-medic-agentw.exe"
    assert container.executables.elevated_helper == scripts / "windows-medic-elevated.exe"
    assert container.runtime.package_version == windows_medic.__version__
    assert isinstance(container.workspace, LocalWorkspace)
    registry = container.startup_registry
    assert isinstance(registry, SchtasksStartupRegistry)
    assert registry.user == "DESKTOP\\dev"
    assert registry.task_name == "WindowsMedic\\Agent"
    assert isinstance(container.instance_guard, NamedMutexGuard)
    assert isinstance(container.run_doctor, RunDoctor)
    assert isinstance(container.show_status, ShowStatus)
    assert isinstance(container.install_agent, InstallAgent)
    assert isinstance(container.uninstall_agent, UninstallAgent)
    assert isinstance(container.init_config, InitConfig)


def test_compose_reports_a_present_config_file_in_locations(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "config.toml").write_text("[logging]\nlevel = 'debug'\n", encoding="utf-8")
    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    assert container.locations.config_present is True
    registry = container.startup_registry
    assert isinstance(registry, SchtasksStartupRegistry)
    assert registry.user == ""  # no USERNAME in this environment


def test_compose_can_add_a_bounded_json_log_file(
    root_logger_state: None, environ: dict[str, str], tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    log_file = tmp_path / "data" / "logs" / "agent.log"
    container = compose(environ=environ, log_stream=io.StringIO(), log_file=log_file)
    request.addfinalizer(container.close)

    logging.getLogger("windows_medic.probe").info("probe.event")
    container.close()

    events = [json.loads(line)["event"] for line in log_file.read_text("utf-8").splitlines()]
    assert "config.loaded" in events
    assert "probe.event" in events
    logging.getLogger("windows_medic.probe").info("after.close")
    assert "after.close" not in log_file.read_text("utf-8")
