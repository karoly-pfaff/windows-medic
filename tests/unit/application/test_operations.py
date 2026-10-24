"""Operational use cases: doctor, status, install/uninstall, config init. Fakes only."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path, PurePath

import pytest

from tests.builders import T0, identity, incident, process, process_snapshot
from tests.fakes import (
    FakeClock,
    FakeIncidentRepository,
    FakeInstanceGuard,
    FakeProcessReader,
    FakeProcessWorld,
    FakeRepairAudit,
    FakeStartupRegistry,
    FakeWorkspace,
)
from windows_medic.application.operations import (
    Executables,
    Locations,
    Runtime,
    agent_command,
    agent_processes,
)
from windows_medic.application.ports.startup_registry import Registration
from windows_medic.application.use_cases.doctor import CheckStatus, RunDoctor
from windows_medic.application.use_cases.init_config import InitConfig
from windows_medic.application.use_cases.install_agent import (
    InstallAgent,
    UninstallAgent,
    WaitLimits,
)
from windows_medic.application.use_cases.list_recent_incidents import (
    IncidentListLimits,
    ListRecentIncidents,
)
from windows_medic.application.use_cases.list_recent_repairs import (
    ListRecentRepairs,
    RepairListLimits,
)
from windows_medic.application.use_cases.show_status import AgentState, ShowStatus
from windows_medic.domain.errors import StartupRegistrationError, WorkspaceError
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessObservation

DATA = Path("C:/Users/dev/AppData/Local/WindowsMedic")
SCRIPTS = Path("C:/venv/Scripts")
LOCATIONS = Locations(
    data_dir=DATA,
    config_file=DATA / "config.toml",
    config_present=False,
    database=DATA / "incidents.sqlite3",
    log_dir=DATA / "logs",
    log_file=DATA / "logs" / "windows-medic-agent.log",
    elevated_dir=DATA / "elevated",
)
EXECUTABLES = Executables(
    cli=SCRIPTS / "windows-medic.exe",
    agent=SCRIPTS / "windows-medic-agent.exe",
    agent_gui=SCRIPTS / "windows-medic-agentw.exe",
    mcp_server=SCRIPTS / "windows-medic-mcp.exe",
    elevated_helper=SCRIPTS / "windows-medic-elevated.exe",
)
RUNTIME = Runtime("0.1.0", "3.13.7", Path("C:/venv/Scripts/python.exe"))
DEFAULT_CONFIG = "# Windows Medic configuration.\n[sampling]\n# base_interval_seconds = 5.0\n"
OWN_PID = 4242


def installed_workspace(*, config: bool = True) -> FakeWorkspace:
    workspace = FakeWorkspace()
    for directory in (DATA, DATA / "logs", DATA / "elevated"):
        workspace.directories.add(directory)
    for exe in EXECUTABLES.all():
        workspace.files[exe] = "MZ"
    workspace.files[LOCATIONS.database] = "x" * 4096
    if config:
        workspace.files[LOCATIONS.config_file] = DEFAULT_CONFIG
    return workspace


def agent_launcher(pid: int = 500) -> tuple[ProcessObservation, ProcessObservation]:
    """The launcher exe and the Python it started, as psutil would show them."""
    launcher = process(pid, name="windows-medic-agentw.exe")
    child = replace(
        process(pid + 1, name="python.exe", parent_pid=pid),
        exe_path=str(SCRIPTS / "python.exe"),
        command_line=(
            str(SCRIPTS / "python.exe"),
            str(EXECUTABLES.agent_gui),
            "--log-file",
            str(LOCATIONS.log_file),
        ),
    )
    return launcher, child


class TestAgentProcesses:
    def test_matches_the_launcher_by_name_and_the_python_child_by_command_line(self) -> None:
        launcher, child = agent_launcher()
        bystander = process(7, name="python.exe")
        nameless = process(8, name=Unavailable(UnavailableReason.ACCESS_DENIED), parent_pid=1)
        cli = process(9, name="windows-medic.exe")

        found = agent_processes((launcher, child, bystander, nameless, cli), EXECUTABLES)

        assert [o.identity.pid for o in found] == [500, 501]

    def test_a_program_merely_mentioning_the_launcher_is_not_an_agent(self) -> None:
        # `uninstall-agent --stop` must never terminate an editor that has the file open.
        agent_path = str(EXECUTABLES.agent)
        editor = replace(process(20, name="notepad.exe"), command_line=("notepad.exe", agent_path))
        script = replace(
            process(21, name="python.exe"),
            command_line=("python.exe", "inspect_binaries.py", agent_path),
        )

        assert agent_processes((editor, script), EXECUTABLES) == ()

    def test_any_python_interpreter_running_the_launcher_script_is_an_agent(self) -> None:
        orphan = replace(
            process(30, name="pythonw.exe", parent_pid=1),
            command_line=("C:\\Python313\\pythonw.exe", str(EXECUTABLES.agent_gui)),
        )

        assert agent_processes((orphan,), EXECUTABLES) == (orphan,)

    def test_agent_command_runs_the_windowless_launcher_with_a_log_file(self) -> None:
        assert agent_command(EXECUTABLES, LOCATIONS) == (
            str(EXECUTABLES.agent_gui),
            "--log-file",
            str(LOCATIONS.log_file),
        )


class DoctorHarness:
    def __init__(
        self,
        *,
        workspace: FakeWorkspace | None = None,
        registry: FakeStartupRegistry | None = None,
        guard: FakeInstanceGuard | None = None,
        processes: tuple[ProcessObservation, ...] = (),
        locations: Locations = LOCATIONS,
        high_risk_enabled: bool = False,
    ) -> None:
        self.workspace = workspace if workspace is not None else installed_workspace()
        self.registry = (
            registry
            if registry is not None
            else FakeStartupRegistry(command=agent_command(EXECUTABLES, LOCATIONS))
        )
        self.guard = guard if guard is not None else FakeInstanceGuard(held=True)
        self.incidents = FakeIncidentRepository()
        self.reader = FakeProcessReader(process_snapshot(*processes))
        self.doctor = RunDoctor(
            workspace=self.workspace,
            startup=self.registry,
            guard=self.guard,
            process_reader=self.reader,
            incidents=ListRecentIncidents(self.incidents, IncidentListLimits(max_limit=20)),
            locations=locations,
            executables=EXECUTABLES,
            runtime=RUNTIME,
            high_risk_enabled=high_risk_enabled,
        )

    def check(self, name: str) -> tuple[CheckStatus, str]:
        report = self.doctor.execute()
        [check] = [c for c in report.checks if c.name == name]
        return check.status, check.detail


class TestRunDoctor:
    def test_a_complete_installation_is_healthy_and_explains_every_check(self) -> None:
        h = DoctorHarness(processes=agent_launcher())

        report = h.doctor.execute()

        assert report.healthy is True
        assert [c.name for c in report.checks] == [
            "runtime",
            "configuration",
            "data_directory",
            "database",
            "executables",
            "startup",
            "agent",
            "elevation",
        ]
        assert all(c.status is CheckStatus.OK for c in report.checks)
        assert "windows-medic 0.1.0 on Python 3.13.7" in report.checks[0].detail
        assert "built-in defaults" in report.checks[1].detail
        assert "0.0 MiB" in report.checks[3].detail
        assert "pids 500, 501" in report.checks[6].detail
        assert h.guard.held is True  # the probe lease was released; the agent still owns it

    def test_a_present_config_file_is_reported_as_loaded(self) -> None:
        loaded = replace(LOCATIONS, config_present=True)
        h = DoctorHarness(locations=loaded)

        assert h.check("configuration") == (CheckStatus.OK, f"loaded {LOCATIONS.config_file}")

    def test_an_unwritable_data_directory_fails(self) -> None:
        h = DoctorHarness(workspace=FakeWorkspace(unwritable="access is denied"))

        report = h.doctor.execute()

        [check] = [c for c in report.checks if c.name == "data_directory"]
        assert check.status is CheckStatus.FAILED
        assert "access is denied" in check.detail
        assert report.healthy is False

    def test_a_database_that_cannot_answer_fails(self) -> None:
        h = DoctorHarness()
        h.incidents.fail_reads = "database disk image is malformed"

        status, detail = h.check("database")

        assert status is CheckStatus.FAILED
        assert "malformed" in detail

    def test_an_absent_database_is_reported_as_absent_but_healthy(self) -> None:
        workspace = installed_workspace()
        del workspace.files[LOCATIONS.database]
        h = DoctorHarness(workspace=workspace)

        assert h.check("database") == (
            CheckStatus.OK,
            f"{LOCATIONS.database} (absent) opens and answers queries",
        )

    def test_missing_executables_fail_and_are_listed(self) -> None:
        workspace = installed_workspace()
        del workspace.files[EXECUTABLES.elevated_helper]
        h = DoctorHarness(workspace=workspace)

        status, detail = h.check("executables")

        assert status is CheckStatus.FAILED
        assert str(EXECUTABLES.elevated_helper) in detail
        assert "uv sync" in detail

    @pytest.mark.parametrize(
        ("registry", "expected"),
        [
            (FakeStartupRegistry(), "no logon task"),
            (FakeStartupRegistry(command=("x",)), "logon task runs: x"),
        ],
    )
    def test_startup_registration_is_reported(
        self, registry: FakeStartupRegistry, expected: str
    ) -> None:
        h = DoctorHarness(registry=registry)

        status, detail = h.check("startup")

        assert expected in detail
        assert status is (CheckStatus.OK if registry.command is not None else CheckStatus.WARNING)

    def test_an_unknown_startup_state_warns_with_the_reason(self) -> None:
        registry = FakeStartupRegistry()
        registry.unknown = "schtasks exited with code 2"
        h = DoctorHarness(registry=registry)

        assert h.check("startup") == (
            CheckStatus.WARNING,
            "logon task state unknown: schtasks exited with code 2",
        )

    def test_a_stopped_agent_warns_and_says_how_to_start_it(self) -> None:
        h = DoctorHarness(guard=FakeInstanceGuard(held=False))

        status, detail = h.check("agent")

        assert status is CheckStatus.WARNING
        assert "install-agent" in detail
        assert h.guard.held is False  # the probe lease was released again

    def test_elevation_is_a_warning_when_high_risk_repairs_are_enabled(self) -> None:
        disabled = DoctorHarness().check("elevation")
        status, detail = DoctorHarness(high_risk_enabled=True).check("elevation")

        assert disabled == (CheckStatus.OK, "high-risk repairs disabled; nothing is elevated")
        assert status is CheckStatus.WARNING
        assert str(EXECUTABLES.elevated_helper) in detail
        assert "writable by your account" in detail
        assert "only approve a UAC prompt you started yourself" in detail

    def test_agent_processes_without_the_lock_are_suspicious(self) -> None:
        h = DoctorHarness(guard=FakeInstanceGuard(held=False), processes=agent_launcher())

        status, detail = h.check("agent")

        assert status is CheckStatus.WARNING
        assert "pids 500, 501" in detail
        assert "lock is free" in detail

    def test_a_running_agent_with_no_visible_process_still_counts(self) -> None:
        h = DoctorHarness(guard=FakeInstanceGuard(held=True))

        assert h.check("agent") == (
            CheckStatus.OK,
            "running (single-instance lock held; pids ?)",
        )

    def test_a_failing_process_inventory_fails_the_agent_check(self) -> None:
        h = DoctorHarness()
        h.reader.fail_next = "process inventory unavailable"

        status, detail = h.check("agent")

        assert status is CheckStatus.FAILED
        assert "process inventory unavailable" in detail


class TestShowStatus:
    def make(
        self, *, guard_held: bool = True, processes: tuple[ProcessObservation, ...] = ()
    ) -> tuple[ShowStatus, FakeIncidentRepository, FakeRepairAudit]:
        incidents = FakeIncidentRepository()
        audit = FakeRepairAudit()
        status = ShowStatus(
            startup=FakeStartupRegistry(command=agent_command(EXECUTABLES, LOCATIONS)),
            guard=FakeInstanceGuard(held=guard_held),
            process_reader=FakeProcessReader(process_snapshot(*processes)),
            incidents=ListRecentIncidents(incidents, IncidentListLimits(max_limit=20)),
            repairs=ListRecentRepairs(audit, RepairListLimits(max_limit=20)),
            locations=LOCATIONS,
            executables=EXECUTABLES,
            runtime=RUNTIME,
        )
        return status, incidents, audit

    def test_reports_locations_agent_state_and_latest_records(self) -> None:
        status, incidents, _ = self.make(processes=agent_launcher())
        incidents.save(incident("inc-old", started_at=T0 - timedelta(hours=2)))
        incidents.save(incident("inc-new", started_at=T0 - timedelta(minutes=5)))

        report = status.execute()

        assert report.locations is LOCATIONS
        assert report.agent.running is True
        assert report.agent.pids == (500, 501)
        assert report.startup.registration is Registration.REGISTERED
        assert report.latest_incident is not None
        assert report.latest_incident.id == "inc-new"
        assert report.latest_repair is None
        assert report.store_problem is None

    def test_a_stopped_agent_and_an_empty_store(self) -> None:
        status, _, _ = self.make(guard_held=False)

        report = status.execute()

        assert report.agent.running is False
        assert report.agent.pids == ()
        assert report.latest_incident is None

    def test_a_broken_store_is_reported_not_raised(self) -> None:
        status, incidents, _ = self.make()
        incidents.fail_reads = "database is locked"

        report = status.execute()

        assert report.store_problem == "database is locked"
        assert report.latest_incident is None

    def test_an_unavailable_process_inventory_leaves_pids_empty(self) -> None:
        status, _, _ = self.make()
        reader = FakeProcessReader(process_snapshot())
        reader.fail_next = "boom"
        status = ShowStatus(
            startup=FakeStartupRegistry(),
            guard=FakeInstanceGuard(held=True),
            process_reader=reader,
            incidents=ListRecentIncidents(
                FakeIncidentRepository(), IncidentListLimits(max_limit=1)
            ),
            repairs=ListRecentRepairs(FakeRepairAudit(), RepairListLimits(max_limit=1)),
            locations=LOCATIONS,
            executables=EXECUTABLES,
            runtime=RUNTIME,
        )

        report = status.execute()

        assert report.agent == AgentState(running=True, pids=())


class TestInitConfig:
    def test_writes_the_rendered_defaults_into_the_data_directory(self) -> None:
        workspace = FakeWorkspace()
        use_case = InitConfig(
            workspace=workspace, locations=LOCATIONS, render_config=lambda: DEFAULT_CONFIG
        )

        written = use_case.execute(force=False)

        assert written == LOCATIONS.config_file
        assert workspace.files[LOCATIONS.config_file] == DEFAULT_CONFIG
        assert DATA in workspace.directories

    def test_refuses_to_overwrite_unless_forced(self) -> None:
        workspace = installed_workspace()
        workspace.files[LOCATIONS.config_file] = "custom = true\n"
        use_case = InitConfig(
            workspace=workspace, locations=LOCATIONS, render_config=lambda: DEFAULT_CONFIG
        )

        with pytest.raises(WorkspaceError, match="already exists"):
            use_case.execute(force=False)
        assert workspace.files[LOCATIONS.config_file] == "custom = true\n"

        use_case.execute(force=True)

        assert workspace.files[LOCATIONS.config_file] == DEFAULT_CONFIG


class InstallHarness:
    def __init__(
        self,
        *,
        workspace: FakeWorkspace | None = None,
        registry: FakeStartupRegistry | None = None,
        guard_held: bool = False,
        agent_starts: bool = True,
    ) -> None:
        self.workspace = workspace if workspace is not None else FakeWorkspace()
        self.registry = registry if registry is not None else FakeStartupRegistry()
        self.guard = FakeInstanceGuard(held=guard_held)
        self.clock = FakeClock(T0)
        if agent_starts:
            # The started agent takes its single-instance lock.
            self.registry.on_run = lambda: setattr(self.guard, "held", True)
        self.install = InstallAgent(
            workspace=self.workspace,
            registry=self.registry,
            guard=self.guard,
            clock=self.clock,
            locations=LOCATIONS,
            executables=EXECUTABLES,
            render_config=lambda: DEFAULT_CONFIG,
            start_wait=WaitLimits(
                timeout=timedelta(seconds=2), interval=timedelta(milliseconds=100)
            ),
        )


class TestInstallAgent:
    def test_creates_the_layout_writes_defaults_registers_and_starts(self) -> None:
        h = InstallHarness()

        report = h.install.execute(start_now=True)

        assert {DATA, DATA / "logs", DATA / "elevated"} <= h.workspace.directories
        assert h.workspace.files[LOCATIONS.config_file] == DEFAULT_CONFIG
        assert report.config_created is True
        assert report.command == agent_command(EXECUTABLES, LOCATIONS)
        assert h.registry.command == report.command
        assert report.startup.registration is Registration.REGISTERED
        assert report.started is True
        assert report.already_running is False
        assert h.registry.runs == 1

    def test_a_start_is_reported_only_once_the_agent_is_seen_running(self) -> None:
        # schtasks /Run returned 0, but the agent died at once (bad config, missing exe).
        h = InstallHarness(agent_starts=False)

        report = h.install.execute(start_now=True)

        assert h.registry.runs == 1
        assert report.start_requested is True
        assert report.started is False
        assert len(h.clock.sleeps) == 20  # bounded: 2 s at 100 ms

    def test_keeps_an_existing_config_and_replaces_the_registration(self) -> None:
        h = InstallHarness(
            workspace=installed_workspace(), registry=FakeStartupRegistry(command=("old",))
        )
        h.workspace.files[LOCATIONS.config_file] = "custom = true\n"

        report = h.install.execute(start_now=False)

        assert report.config_created is False
        assert h.workspace.files[LOCATIONS.config_file] == "custom = true\n"
        assert h.registry.command == agent_command(EXECUTABLES, LOCATIONS)
        assert report.started is False
        assert h.registry.runs == 0

    def test_does_not_start_a_second_agent(self) -> None:
        h = InstallHarness(guard_held=True)

        report = h.install.execute(start_now=True)

        assert report.already_running is True
        assert report.started is False
        assert h.registry.runs == 0
        assert h.guard.held is True

    def test_registration_failures_propagate_after_the_layout_exists(self) -> None:
        h = InstallHarness(registry=FakeStartupRegistry(broken="Access is denied."))

        with pytest.raises(StartupRegistrationError, match="Access is denied"):
            h.install.execute(start_now=True)

        assert DATA in h.workspace.directories
        assert h.registry.runs == 0

    def test_an_unwritable_data_directory_stops_before_registering(self) -> None:
        h = InstallHarness(workspace=FakeWorkspace(unwritable="access is denied"))

        with pytest.raises(WorkspaceError, match="access is denied"):
            h.install.execute(start_now=True)

        assert h.registry.command is None


STOP_LIMITS = WaitLimits(timeout=timedelta(seconds=2), interval=timedelta(milliseconds=100))


class UninstallHarness:
    def __init__(
        self,
        *,
        registered: bool = True,
        guard_held: bool = False,
        processes: tuple[ProcessObservation, ...] = (),
        locations: Locations = LOCATIONS,
    ) -> None:
        self.clock = FakeClock(T0)
        self.world = FakeProcessWorld(self.clock, *processes)
        self.workspace = installed_workspace()
        self.registry = (
            FakeStartupRegistry(command=agent_command(EXECUTABLES, LOCATIONS))
            if registered
            else FakeStartupRegistry()
        )
        self.guard = FakeInstanceGuard(held=guard_held)
        # What the data directory still held each time storage was released.
        self.released_with: list[list[PurePath]] = []
        self.uninstall = UninstallAgent(
            workspace=self.workspace,
            registry=self.registry,
            guard=self.guard,
            process_reader=self.world,
            controller=self.world,
            clock=self.clock,
            locations=locations,
            executables=EXECUTABLES,
            own_pid=OWN_PID,
            limits=STOP_LIMITS,
            release_storage=lambda: self.released_with.append(list(self.workspace.removed)),
        )


class TestUninstallAgent:
    def test_removes_the_registration_and_keeps_the_data(self) -> None:
        h = UninstallHarness()

        report = h.uninstall.execute(stop=False, purge_data=False)

        assert report.unregistered is True
        assert h.registry.command is None
        assert report.stopped == ()
        assert report.survivors == ()
        assert report.purged is False
        assert h.workspace.files[LOCATIONS.database]
        assert h.world.terminations == []

    def test_an_absent_registration_is_not_an_error(self) -> None:
        h = UninstallHarness(registered=False)

        assert h.uninstall.execute(stop=False, purge_data=False).unregistered is False

    def test_stop_terminates_agent_processes_by_exact_identity_and_waits(self) -> None:
        launcher, child = agent_launcher()
        h = UninstallHarness(
            guard_held=True, processes=(launcher, child, process(7, name="node.exe"))
        )
        h.world.stubborn[child.identity] = 3  # gone at the third snapshot after the signal

        report = h.uninstall.execute(stop=True, purge_data=False)

        assert h.world.terminations == [launcher.identity, child.identity]
        assert report.stopped == (launcher.identity, child.identity)
        assert report.survivors == ()
        assert h.clock.sleeps == [0.1, 0.1]
        assert identity(7) in h.world.live

    def test_stop_never_targets_the_calling_process(self) -> None:
        me = process(OWN_PID, name="windows-medic-agent.exe")
        h = UninstallHarness(processes=(me,))

        report = h.uninstall.execute(stop=True, purge_data=False)

        assert h.world.terminations == []
        assert report.stopped == ()
        assert identity(OWN_PID) in h.world.live

    def test_stop_reports_survivors_after_the_bounded_wait(self) -> None:
        launcher, child = agent_launcher()
        h = UninstallHarness(processes=(launcher, child))
        h.world.denied.add(child.identity)

        report = h.uninstall.execute(stop=True, purge_data=False)

        assert report.stopped == (launcher.identity,)
        assert report.survivors == (child.identity,)
        assert len(h.clock.sleeps) == 20  # 2 s timeout at 100 ms

    def test_stop_with_nothing_running_does_not_wait(self) -> None:
        h = UninstallHarness()

        report = h.uninstall.execute(stop=True, purge_data=False)

        assert report.stopped == ()
        assert h.clock.sleeps == []

    def test_purge_removes_the_data_directory_once_the_agent_is_gone(self) -> None:
        launcher, child = agent_launcher()
        h = UninstallHarness(processes=(launcher, child))

        for owned in (
            DATA / "incidents.sqlite3-wal",
            DATA / "incidents.sqlite3-shm",
            LOCATIONS.log_file,
            LOCATIONS.log_dir / "windows-medic-agent.log.1",
            LOCATIONS.elevated_dir / "elevated-0123abcd.json",
        ):
            h.workspace.files[owned] = "x"

        report = h.uninstall.execute(stop=True, purge_data=True)

        assert report.purged is True
        assert report.data_dir_removed is True
        assert h.workspace.files.keys() == set(EXECUTABLES.all())  # only the install is left
        assert DATA not in h.workspace.directories
        assert LOCATIONS.log_dir not in h.workspace.directories
        # Windows cannot delete an open database: our own handle goes first, exactly once.
        assert h.released_with == [[]]

    def test_purge_never_deletes_what_windows_medic_did_not_write(self) -> None:
        # WINDOWS_MEDIC_DATA_DIR pointed at a folder that also holds the user's own files.
        h = UninstallHarness()
        theirs = (DATA / "thesis.docx", LOCATIONS.log_dir / "build.log", DATA / "notes" / "a.txt")
        h.workspace.directories.add(DATA / "notes")
        for path in theirs:
            h.workspace.files[path] = "precious"

        report = h.uninstall.execute(stop=False, purge_data=True)

        assert report.purged is True
        assert report.data_dir_removed is False
        assert all(path in h.workspace.files for path in theirs)
        assert LOCATIONS.database not in h.workspace.files
        assert LOCATIONS.config_file not in h.workspace.files
        assert DATA in h.workspace.directories
        assert LOCATIONS.elevated_dir not in h.workspace.directories  # ours and empty

    def test_purge_keeps_a_configuration_file_outside_the_data_directory(self) -> None:
        elsewhere = Path("C:/Users/dev/dotfiles/windows-medic.toml")
        h = UninstallHarness(locations=replace(LOCATIONS, config_file=elsewhere))
        h.workspace.files[elsewhere] = DEFAULT_CONFIG

        h.uninstall.execute(stop=False, purge_data=True)

        assert elsewhere in h.workspace.files

    def test_storage_is_kept_open_unless_purging(self) -> None:
        h = UninstallHarness()

        h.uninstall.execute(stop=True, purge_data=False)

        assert h.released_with == []

    def test_purge_refuses_while_an_agent_still_runs(self) -> None:
        h = UninstallHarness(guard_held=True)

        with pytest.raises(WorkspaceError, match="still running"):
            h.uninstall.execute(stop=False, purge_data=True)

        assert h.workspace.removed == []
        assert h.released_with == []
        assert h.registry.command is None  # unregistration happened first

    def test_purge_refuses_when_a_survivor_remains(self) -> None:
        launcher, child = agent_launcher()
        h = UninstallHarness(processes=(launcher, child))
        h.world.denied.add(launcher.identity)

        with pytest.raises(WorkspaceError, match="pid 500"):
            h.uninstall.execute(stop=True, purge_data=True)

        assert h.workspace.removed == []

    def test_stop_limits_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="interval"):
            WaitLimits(timeout=timedelta(seconds=1), interval=timedelta(0))
        with pytest.raises(ValueError, match="timeout"):
            WaitLimits(timeout=timedelta(0), interval=timedelta(milliseconds=50))
