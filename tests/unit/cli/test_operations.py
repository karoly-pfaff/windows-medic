"""`windows-medic doctor|status|install-agent|uninstall-agent|config|mcp-config`."""

import io
import json
from collections.abc import Mapping
from dataclasses import replace
from typing import TextIO

import pytest

from tests.builders import BOOT, T0, identity, incident, process, process_snapshot
from tests.containers import DATA_DIR, EXECUTABLES, LOCATIONS, RUNTIME, fake_container
from tests.fakes import (
    FakeClock,
    FakeIncidentRepository,
    FakeInstanceGuard,
    FakeProcessReader,
    FakeProcessWorld,
    FakeStartupRegistry,
    FakeWorkspace,
)
from windows_medic.application.operations import agent_command
from windows_medic.application.use_cases.doctor import CheckStatus, DoctorCheck, DoctorReport
from windows_medic.application.use_cases.show_status import AgentState, StatusReport
from windows_medic.domain.models.repair import (
    RejectionReason,
    RepairAction,
    RepairRecord,
    RepairScope,
    RepairStatus,
)
from windows_medic_cli import main as cli_main
from windows_medic_cli.render import render_doctor, render_status
from windows_medic_root.container import Container


def composer(built: Container) -> cli_main.Composer:
    def compose(
        program: str, *, environ: Mapping[str, str], log_stream: TextIO, error_stream: TextIO
    ) -> Container | None:
        return built

    return compose


def run(*argv: str, built: Container) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = cli_main.main(
        list(argv), environ={}, stdout=stdout, stderr=stderr, compose=composer(built)
    )
    return code, stdout.getvalue(), stderr.getvalue()


def installed_workspace() -> FakeWorkspace:
    workspace = FakeWorkspace()
    for directory in (LOCATIONS.data_dir, LOCATIONS.log_dir, LOCATIONS.elevated_dir):
        workspace.directories.add(directory)
    for exe in EXECUTABLES.all():
        workspace.files[exe] = "MZ"
    workspace.files[LOCATIONS.database] = "x" * 2048
    return workspace


class TestDoctor:
    def test_healthy_installation_exits_zero_and_lists_every_check(self) -> None:
        built = fake_container(
            workspace=installed_workspace(),
            startup_registry=FakeStartupRegistry(command=agent_command(EXECUTABLES, LOCATIONS)),
            instance_guard=FakeInstanceGuard(held=True),
        )

        code, out, err = run("doctor", built=built)

        assert code == 0, err
        assert out.startswith("Windows Medic doctor\n")
        for name in (
            "runtime",
            "configuration",
            "data_directory",
            "database",
            "executables",
            "startup",
            "agent",
            "elevation",
        ):
            assert f"[ok] {name}:" in out
        assert "All checks passed." in out

    def test_a_failed_check_exits_one_and_a_warning_does_not(self) -> None:
        stopped = fake_container(workspace=installed_workspace())
        unwritable = installed_workspace()
        unwritable.unwritable = "access is denied"
        broken = fake_container(workspace=unwritable)

        warning_code, warning_out, _ = run("doctor", built=stopped)
        failed_code, failed_out, _ = run("doctor", built=broken)

        assert warning_code == 0
        assert "[warning] agent:" in warning_out
        assert "[warning] startup:" in warning_out
        assert "install-agent" in warning_out
        assert failed_code == 1
        assert "[failed] data_directory:" in failed_out
        assert "access is denied" in failed_out
        assert "1 check failed, 2 warnings." in failed_out


class TestStatus:
    def test_reports_locations_agent_startup_and_latest_records(self) -> None:
        incidents = FakeIncidentRepository()
        incidents.save(incident("inc-1", started_at=T0))
        launcher = process(500, name="windows-medic-agentw.exe")
        built = fake_container(
            incident_repository=incidents,
            process_reader=FakeProcessReader(process_snapshot(launcher)),
            startup_registry=FakeStartupRegistry(command=agent_command(EXECUTABLES, LOCATIONS)),
            instance_guard=FakeInstanceGuard(held=True),
        )

        code, out, err = run("status", built=built)

        assert code == 0, err
        assert "windows-medic 0.1.0 (Python 3.13.7" in out
        assert f"Data directory:  {DATA_DIR}" in out
        assert f"Configuration:   {LOCATIONS.config_file} (absent; built-in defaults" in out
        assert f"Database:        {LOCATIONS.database}" in out
        assert f"Agent log:       {LOCATIONS.log_file}" in out
        assert "Agent:           running (pid 500)" in out
        assert "Startup:         registered (" in out
        assert "Latest incident: inc-1" in out
        assert "Latest repair:   none" in out

    def test_a_stopped_agent_without_registration_and_an_empty_store(self) -> None:
        built = fake_container()

        code, out, _ = run("status", built=built)

        assert code == 0
        assert "Agent:           not running" in out
        assert "Startup:         not registered (run `windows-medic install-agent`)" in out
        assert "Latest incident: none" in out

    def test_a_broken_store_is_shown_but_does_not_fail_the_command(self) -> None:
        incidents = FakeIncidentRepository()
        incidents.fail_reads = "database is locked"
        built = fake_container(incident_repository=incidents)

        code, out, _ = run("status", built=built)

        assert code == 0
        assert "Store problem:   database is locked" in out

    def test_bare_invocation_shows_locations_and_commands_without_probing(self) -> None:
        guard = FakeInstanceGuard()
        built = fake_container(instance_guard=guard)

        code, out, _ = run(built=built)

        assert code == 0
        assert "windows-medic 0.1.0" in out
        assert f"Data directory:  {DATA_DIR}" in out
        assert f"Agent log:       {LOCATIONS.log_file}" in out
        assert "Commands: health, diagnose, inspect" in out
        assert "doctor, status, install-agent" in out
        assert guard.attempts == 0


class TestInstallAgent:
    def test_creates_layout_registers_and_starts(self) -> None:
        registry = FakeStartupRegistry()
        guard = FakeInstanceGuard()
        registry.on_run = lambda: setattr(guard, "held", True)  # the agent takes its lock
        workspace = FakeWorkspace()
        built = fake_container(workspace=workspace, startup_registry=registry, instance_guard=guard)

        code, out, err = run("install-agent", built=built)

        assert code == 0, err
        assert registry.command == agent_command(EXECUTABLES, LOCATIONS)
        assert registry.runs == 1
        assert f"Configuration written: {LOCATIONS.config_file}" in out
        assert "Logon task registered: " in out
        assert str(EXECUTABLES.agent_gui) in out
        assert "Agent started." in out
        assert "windows-medic doctor" in out

    def test_an_agent_that_never_comes_up_is_not_reported_as_started(self) -> None:
        built = fake_container(workspace=FakeWorkspace(), startup_registry=FakeStartupRegistry())

        code, out, _ = run("install-agent", built=built)

        assert code == 0
        assert "Agent started." not in out
        assert "Agent start requested, but it was not seen running" in out
        assert str(LOCATIONS.log_file) in out

    def test_no_start_keeps_the_config_and_only_registers(self) -> None:
        registry = FakeStartupRegistry()
        workspace = installed_workspace()
        workspace.files[LOCATIONS.config_file] = "custom = true\n"
        built = fake_container(workspace=workspace, startup_registry=registry)

        code, out, _ = run("install-agent", "--no-start", built=built)

        assert code == 0
        assert registry.runs == 0
        assert f"Configuration kept: {LOCATIONS.config_file}" in out
        assert "Agent not started (--no-start); it starts at your next logon." in out

    def test_an_already_running_agent_is_left_alone(self) -> None:
        built = fake_container(instance_guard=FakeInstanceGuard(held=True))

        code, out, _ = run("install-agent", built=built)

        assert code == 0
        assert "Agent already running; not started again." in out

    def test_registration_failure_is_reported_with_exit_one(self) -> None:
        built = fake_container(startup_registry=FakeStartupRegistry(broken="Access is denied."))

        code, out, err = run("install-agent", built=built)

        assert code == 1
        assert out == ""
        assert err == "windows-medic: Access is denied.\n"


class TestUninstallAgent:
    def test_removes_registration_and_keeps_data_by_default(self) -> None:
        registry = FakeStartupRegistry(command=agent_command(EXECUTABLES, LOCATIONS))
        workspace = installed_workspace()
        built = fake_container(workspace=workspace, startup_registry=registry)

        code, out, err = run("uninstall-agent", built=built)

        assert code == 0, err
        assert registry.command is None
        assert "Logon task removed." in out
        assert f"Data kept in {DATA_DIR}" in out
        assert "--purge-data" in out
        assert LOCATIONS.database in workspace.files

    def test_stop_terminates_agents_and_reports_them(self) -> None:
        world = FakeProcessWorld(
            FakeClock(T0), process(500, name="windows-medic-agentw.exe", created=BOOT)
        )
        built = fake_container(
            process_reader=world,
            process_controller=world,
            startup_registry=FakeStartupRegistry(),
        )

        code, out, _ = run("uninstall-agent", "--stop", built=built)

        assert code == 0
        assert "No logon task was registered." in out
        assert "Agent stopped: pid 500" in out
        assert world.live == {}

    def test_survivors_fail_the_command(self) -> None:
        world = FakeProcessWorld(FakeClock(T0), process(500, name="windows-medic-agentw.exe"))
        world.denied.add(process(500).identity)
        built = fake_container(process_reader=world, process_controller=world)

        code, out, _ = run("uninstall-agent", "--stop", built=built)

        assert code == 1
        assert "Still running: pid 500" in out

    def test_purge_removes_the_data_directory(self) -> None:
        workspace = installed_workspace()
        built = fake_container(workspace=workspace)

        code, out, _ = run("uninstall-agent", "--purge-data", built=built)

        assert code == 0
        assert f"Data removed: {DATA_DIR}" in out
        assert LOCATIONS.database not in workspace.files

    def test_purge_refuses_while_the_agent_runs(self) -> None:
        built = fake_container(instance_guard=FakeInstanceGuard(held=True))

        code, _, err = run("uninstall-agent", "--purge-data", built=built)

        assert code == 1
        assert "still running" in err


class TestConfig:
    def test_init_writes_defaults_and_refuses_to_overwrite_without_force(self) -> None:
        workspace = FakeWorkspace()
        built = fake_container(workspace=workspace)

        first_code, first_out, _ = run("config", "init", built=built)
        second_code, _, second_err = run("config", "init", built=built)
        forced_code, forced_out, _ = run("config", "init", "--force", built=built)

        assert first_code == 0
        assert first_out == f"Configuration written: {LOCATIONS.config_file}\n"
        assert second_code == 1
        assert "already exists" in second_err
        assert forced_code == 0
        assert forced_out == first_out
        assert workspace.files[LOCATIONS.config_file].startswith("# Windows Medic configuration.")

    def test_check_reports_the_effective_configuration_source(self) -> None:
        built = fake_container()

        code, out, _ = run("config", "check", built=built)

        assert code == 0
        assert f"Configuration: {LOCATIONS.config_file} (absent; built-in defaults" in out
        assert "config init" in out
        assert "cpu_percent = 90.0" in out

    def test_config_without_a_subcommand_is_a_usage_error(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            run("config", built=fake_container())

        assert excinfo.value.code == 2


class TestMcpConfig:
    def test_prints_a_claude_code_mcp_json_snippet_with_the_absolute_server_path(self) -> None:
        built = fake_container()

        code, out, _ = run("mcp-config", built=built)

        assert code == 0
        heading, _, snippet = out.partition("\n\n")
        assert "Claude Code MCP configuration" in heading
        document = json.loads(snippet)
        assert document == {
            "mcpServers": {"windows-medic": {"command": str(EXECUTABLES.mcp_server), "args": []}}
        }


class TestRendering:
    def test_status_shows_a_loaded_config_an_unknown_task_and_the_latest_repair(self) -> None:
        registry = FakeStartupRegistry()
        registry.unknown = "schtasks exited with code 2"
        report = StatusReport(
            runtime=RUNTIME,
            locations=replace(LOCATIONS, config_present=True),
            executables=EXECUTABLES,
            agent=AgentState(running=True, pids=()),
            startup=registry.state(),
            latest_incident=None,
            latest_repair=rejected_repair(),
            store_problem=None,
        )

        out = render_status(report)

        assert f"Configuration:   {LOCATIONS.config_file} (loaded)" in out
        assert "Agent:           running (pid unknown)" in out
        assert "Startup:         unknown (schtasks exited with code 2)" in out
        assert "Latest repair:   rep-1 process.terminate pid 10 @ " in out
        assert "rejected (target_protected), requested 2026-09-11T12:00:00+00:00" in out

    def test_doctor_summary_counts_failures_without_warnings(self) -> None:
        report = DoctorReport(
            (
                DoctorCheck("runtime", CheckStatus.OK, "fine"),
                DoctorCheck("database", CheckStatus.FAILED, "malformed"),
            )
        )

        out = render_doctor(report)

        assert out.endswith("1 check failed.\n")


def rejected_repair() -> RepairRecord:
    return RepairRecord(
        id="rep-1",
        action=RepairAction.PROCESS_TERMINATE,
        scope=RepairScope.PROCESS,
        status=RepairStatus.REJECTED,
        requested_at=T0,
        completed_at=T0,
        target=identity(10),
        port=None,
        risk=None,
        requires_elevation=False,
        rejection=RejectionReason.TARGET_PROTECTED,
        members=(),
        appeared=(),
        verification=None,
    )
