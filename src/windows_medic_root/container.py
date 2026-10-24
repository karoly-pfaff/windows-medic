"""Composition root.

This is the only place that knows about concrete adapters. Entry points call
:func:`compose` once and receive a :class:`Container`; nothing else reads the environment.
"""

import io
import logging
import os
import platform
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from pathlib import Path
from typing import TextIO

import windows_medic
from windows_medic.application.observability import log_event
from windows_medic.application.operations import AGENT_LOG_NAME, Executables, Locations, Runtime
from windows_medic.application.ports.clock import Clock
from windows_medic.application.ports.component_controller import ComponentController
from windows_medic.application.ports.elevation import ElevatedHelper
from windows_medic.application.ports.hung_window_reader import HungWindowReader
from windows_medic.application.ports.incident_repository import IncidentRepository
from windows_medic.application.ports.instance_guard import InstanceGuard
from windows_medic.application.ports.network_reader import NetworkReader
from windows_medic.application.ports.process_controller import ProcessController
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.ports.repair_audit import RepairAuditRepository
from windows_medic.application.ports.startup_registry import StartupRegistry
from windows_medic.application.ports.system_reader import SystemReader
from windows_medic.application.ports.workspace import Workspace
from windows_medic.application.services.repair_audit_trail import RepairAuditTrail
from windows_medic.application.services.repair_executor import RepairExecutor, RepairLimits
from windows_medic.application.use_cases.clear_port import ClearPort
from windows_medic.application.use_cases.diagnose_slowdown import (
    DiagnoseSlowdown,
    DiagnosisLimits,
    DiagnosisPolicy,
)
from windows_medic.application.use_cases.doctor import RunDoctor
from windows_medic.application.use_cases.get_system_health import GetSystemHealth, HealthLimits
from windows_medic.application.use_cases.init_config import InitConfig
from windows_medic.application.use_cases.inspect_port import InspectPort
from windows_medic.application.use_cases.inspect_process import InspectionLimits, InspectProcess
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
from windows_medic.application.use_cases.restart_windows_component import (
    ComponentRepairLimits,
    RestartWindowsComponent,
)
from windows_medic.application.use_cases.show_status import ShowStatus
from windows_medic.application.use_cases.terminate_process import TerminateProcess
from windows_medic.domain.policies.finding_assembly import FindingLimits
from windows_medic.domain.policies.pressure import PressureThresholds
from windows_medic.domain.policies.process_classification import DevelopmentClassifier
from windows_medic.domain.policies.protection import ProtectionPolicy
from windows_medic.domain.policies.resource_hogs import HogThresholds
from windows_medic.domain.policies.risk_markers import AncestryPolicy
from windows_medic.infrastructure.config.default_config import (
    render_default_config,
    render_effective_config,
)
from windows_medic.infrastructure.config.settings import (
    CONFIG_FILE_NAME,
    ConfigurationError,
    Settings,
    load_settings,
)
from windows_medic.infrastructure.filesystem.local_workspace import LocalWorkspace
from windows_medic.infrastructure.observability.structured_logging import (
    close_file_logging,
    configure_file_logging,
    configure_logging,
)
from windows_medic.infrastructure.persistence.sqlite_connection import (
    DatabaseOpenError,
    open_database,
)
from windows_medic.infrastructure.persistence.sqlite_incident_repository import (
    SqliteIncidentRepository,
)
from windows_medic.infrastructure.persistence.sqlite_repair_audit import (
    SqliteRepairAuditRepository,
)
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic.infrastructure.windows.component_controller import (
    WindowsComponentController,
)
from windows_medic.infrastructure.windows.elevation_helper import helper_executable
from windows_medic.infrastructure.windows.elevation_launcher import UacElevationLauncher
from windows_medic.infrastructure.windows.hung_window_reader import Win32HungWindowReader
from windows_medic.infrastructure.windows.process_controller import WindowsProcessController
from windows_medic.infrastructure.windows.psutil_network_reader import PsutilNetworkReader
from windows_medic.infrastructure.windows.psutil_system_reader import PsutilSystemReader
from windows_medic.infrastructure.windows.single_instance import NamedMutexGuard, mutex_name
from windows_medic.infrastructure.windows.task_scheduler import SchtasksStartupRegistry
from windows_medic.infrastructure.windows.windows_process_reader import WindowsProcessReader

_logger = logging.getLogger(__name__)

EXIT_CONFIGURATION_ERROR = 2

# Path/command-line components that identify Windows Medic's own processes (console
# scripts and `python -m windows_medic_*`). Not user-configurable.
WINDOWS_MEDIC_MARKERS: tuple[str, ...] = ("windows-medic", "windows_medic")
INCIDENT_DB_NAME = "incidents.sqlite3"
ELEVATED_RESULTS_DIR = "elevated"
LOG_DIR = "logs"
_MIB = 1024**2


@dataclass(frozen=True, slots=True)
class Container:
    """Wired runtime objects for one process. Grows as adapters and use cases are added."""

    settings: Settings
    clock: Clock
    system_reader: SystemReader
    process_reader: ProcessReader
    network_reader: NetworkReader
    incident_repository: IncidentRepository
    repair_audit: RepairAuditRepository
    process_controller: ProcessController
    component_controller: ComponentController
    elevated_helper: ElevatedHelper
    hung_window_reader: HungWindowReader
    protection_policy: ProtectionPolicy
    ancestry_policy: AncestryPolicy
    pressure_thresholds: PressureThresholds
    get_system_health: GetSystemHealth
    inspect_process: InspectProcess
    inspect_port: InspectPort
    list_recent_incidents: ListRecentIncidents
    diagnose_slowdown: DiagnoseSlowdown
    terminate_process: TerminateProcess
    clear_port: ClearPort
    list_recent_repairs: ListRecentRepairs
    restart_windows_component: RestartWindowsComponent
    workspace: Workspace
    startup_registry: StartupRegistry
    instance_guard: InstanceGuard
    locations: Locations
    executables: Executables
    runtime: Runtime
    run_doctor: RunDoctor
    show_status: ShowStatus
    install_agent: InstallAgent
    uninstall_agent: UninstallAgent
    init_config: InitConfig
    describe_config: Callable[[], str]
    """The effective configuration as TOML text (``windows-medic config check``)."""
    closers: tuple[Callable[[], None], ...] = ()

    def close(self) -> None:
        """Release adapter resources (database connection, log file). Idempotent."""
        for closer in self.closers:
            closer()


def installed_executables() -> Executables:
    """The console/GUI scripts uv installs next to the running interpreter."""
    scripts = Path(sys.executable).parent
    return Executables(
        cli=scripts / "windows-medic.exe",
        agent=scripts / "windows-medic-agent.exe",
        agent_gui=scripts / "windows-medic-agentw.exe",
        mcp_server=scripts / "windows-medic-mcp.exe",
        elevated_helper=helper_executable(),
    )


def locations_for(settings: Settings) -> Locations:
    data_dir = settings.data_dir
    return Locations(
        data_dir=data_dir,
        config_file=settings.config_file or data_dir / CONFIG_FILE_NAME,
        config_present=settings.config_file is not None,
        database=data_dir / INCIDENT_DB_NAME,
        log_dir=data_dir / LOG_DIR,
        log_file=data_dir / LOG_DIR / AGENT_LOG_NAME,
        elevated_dir=data_dir / ELEVATED_RESULTS_DIR,
    )


def current_user(environ: Mapping[str, str]) -> str:
    """``DOMAIN\\user`` for Task Scheduler; empty when the environment does not say."""
    name = environ.get("USERNAME", "")
    domain = environ.get("USERDOMAIN", "")
    if name and domain:
        return f"{domain}\\{name}"
    return name


def compose(
    *, environ: Mapping[str, str], log_stream: TextIO, log_file: Path | None = None
) -> Container:
    """Load configuration, configure logging and return the wired container.

    With *log_file*, structured events are also written to that rotating file (the
    agent's mode when started by the logon task, where no console exists).

    Raises:
        ConfigurationError: When configuration is missing, unreadable or invalid. Callers
            (entry points) report the message and exit; nothing else is started.
        DatabaseOpenError: When the incident database cannot be opened or migrated.
    """
    settings = load_settings(environ=environ)
    configure_logging(settings.logging.level, log_stream)
    if log_file is not None:
        configure_file_logging(
            settings.logging.level,
            log_file,
            max_bytes=settings.logging.file_max_bytes,
            backup_count=settings.logging.file_backup_count,
        )
    log_event(
        _logger,
        "config.loaded",
        data_dir=settings.data_dir,
        config_file=settings.config_file,
        log_level=settings.logging.level.value,
        log_file=log_file,
    )
    clock = SystemClock()
    system_reader = PsutilSystemReader(clock)
    process_reader = WindowsProcessReader(clock)
    network_reader = PsutilNetworkReader()
    try:
        database = open_database(settings.data_dir / INCIDENT_DB_NAME)
    except DatabaseOpenError as exc:
        # Logged as well as raised: under the logon task the log file is the only witness.
        log_event(_logger, "storage.unavailable", level=logging.ERROR, error=str(exc))
        if log_file is not None:
            close_file_logging()
        raise
    # The log file closes last so that whatever the other closers log is still recorded.
    closers: list[Callable[[], None]] = [database.close]
    if log_file is not None:
        closers.append(close_file_logging)
    incident_repository = SqliteIncidentRepository(database, clock=clock)
    repair_audit = SqliteRepairAuditRepository(database)
    process_controller = WindowsProcessController()
    component_controller = WindowsComponentController(windows_directory=settings.windows_directory)
    elevated_helper = UacElevationLauncher(
        helper=helper_executable(),
        result_dir=settings.data_dir / ELEVATED_RESULTS_DIR,
        timeout=timedelta(seconds=settings.repairs.elevation_timeout_seconds),
    )
    inspection_limits = InspectionLimits(
        max_ancestors=settings.inspection.max_ancestors,
        max_descendants=settings.inspection.max_descendants,
        max_port_owners=settings.inspection.max_port_owners,
    )
    protection_policy = ProtectionPolicy(
        own_pid=os.getpid(),
        windows_medic_markers=WINDOWS_MEDIC_MARKERS,
        user_protected_names=settings.protection.additional_protected_names,
        windows_directory=str(settings.windows_directory),
    )
    ancestry_policy = AncestryPolicy(
        claude_markers=settings.classifiers.claude_markers,
        terminal_process_names=settings.classifiers.terminal_process_names,
    )
    pressure_thresholds = PressureThresholds(
        cpu_percent=settings.pressure.cpu_percent,
        memory_percent=settings.pressure.memory_percent,
        memory_available_floor_bytes=settings.pressure.memory_available_floor_mib * _MIB,
    )
    health_limits = HealthLimits(
        measurement_window_seconds=settings.health.measurement_window_seconds,
        top_contributors=settings.health.top_contributors,
    )
    hung_window_reader = Win32HungWindowReader(
        limit=settings.diagnosis.max_hung_windows, max_title=settings.diagnosis.max_window_title
    )
    inspect_port = InspectPort(
        process_reader=process_reader,
        network_reader=network_reader,
        protection=protection_policy,
        ancestry=ancestry_policy,
        limits=inspection_limits,
    )
    repairs = settings.repairs
    trail = RepairAuditTrail(
        audit=repair_audit,
        clock=clock,
        retention=timedelta(days=repairs.audit_retention_days),
    )
    executor = RepairExecutor(
        process_reader=process_reader,
        controller=process_controller,
        trail=trail,
        protection=protection_policy,
        ancestry=ancestry_policy,
        limits=RepairLimits(
            verify_timeout=timedelta(seconds=repairs.verify_timeout_seconds),
            verify_interval=timedelta(seconds=repairs.verify_interval_seconds),
            max_tree_members=repairs.max_tree_members,
        ),
    )
    list_recent_incidents = ListRecentIncidents(
        incident_repository, IncidentListLimits(max_limit=settings.incidents.max_list)
    )
    list_recent_repairs = ListRecentRepairs(
        repair_audit, RepairListLimits(max_limit=repairs.max_audit_list)
    )
    workspace = LocalWorkspace()
    startup_registry = SchtasksStartupRegistry(
        schtasks=settings.windows_directory / "System32" / "schtasks.exe",
        user=current_user(environ),
        scratch_dir=settings.data_dir,
    )
    instance_guard = NamedMutexGuard(name=mutex_name(settings.data_dir))
    locations = locations_for(settings)
    executables = installed_executables()
    runtime = Runtime(
        package_version=windows_medic.__version__,
        python_version=platform.python_version(),
        python_executable=Path(sys.executable),
    )
    return Container(
        settings=settings,
        clock=clock,
        system_reader=system_reader,
        process_reader=process_reader,
        network_reader=network_reader,
        incident_repository=incident_repository,
        repair_audit=repair_audit,
        process_controller=process_controller,
        component_controller=component_controller,
        elevated_helper=elevated_helper,
        hung_window_reader=hung_window_reader,
        protection_policy=protection_policy,
        ancestry_policy=ancestry_policy,
        pressure_thresholds=pressure_thresholds,
        inspect_process=InspectProcess(
            process_reader=process_reader,
            protection=protection_policy,
            ancestry=ancestry_policy,
            limits=inspection_limits,
        ),
        inspect_port=inspect_port,
        list_recent_incidents=list_recent_incidents,
        get_system_health=GetSystemHealth(
            system_reader=system_reader,
            process_reader=process_reader,
            clock=clock,
            limits=health_limits,
        ),
        diagnose_slowdown=DiagnoseSlowdown(
            system_reader=system_reader,
            process_reader=process_reader,
            incident_repository=incident_repository,
            hung_window_reader=hung_window_reader,
            clock=clock,
            policy=_diagnosis_policy(
                settings, pressure_thresholds, protection_policy, ancestry_policy
            ),
            limits=_diagnosis_limits(settings, health_limits),
        ),
        terminate_process=TerminateProcess(executor=executor),
        clear_port=ClearPort(
            inspect_port=inspect_port, network_reader=network_reader, executor=executor
        ),
        list_recent_repairs=list_recent_repairs,
        restart_windows_component=RestartWindowsComponent(
            process_reader=process_reader,
            controller=process_controller,
            component_controller=component_controller,
            elevated_helper=elevated_helper,
            trail=trail,
            own_pid=os.getpid(),
            high_risk_enabled=repairs.high_risk_repairs_enabled,
            limits=ComponentRepairLimits(
                verify_timeout=timedelta(seconds=repairs.component_verify_timeout_seconds),
                verify_interval=timedelta(seconds=repairs.component_verify_interval_seconds),
                auto_restart_wait=timedelta(seconds=repairs.explorer_auto_restart_wait_seconds),
            ),
        ),
        workspace=workspace,
        startup_registry=startup_registry,
        instance_guard=instance_guard,
        locations=locations,
        executables=executables,
        runtime=runtime,
        run_doctor=RunDoctor(
            workspace=workspace,
            startup=startup_registry,
            guard=instance_guard,
            process_reader=process_reader,
            incidents=list_recent_incidents,
            locations=locations,
            executables=executables,
            runtime=runtime,
            high_risk_enabled=settings.repairs.high_risk_repairs_enabled,
        ),
        show_status=ShowStatus(
            startup=startup_registry,
            guard=instance_guard,
            process_reader=process_reader,
            incidents=list_recent_incidents,
            repairs=list_recent_repairs,
            locations=locations,
            executables=executables,
            runtime=runtime,
        ),
        install_agent=InstallAgent(
            workspace=workspace,
            registry=startup_registry,
            guard=instance_guard,
            clock=clock,
            locations=locations,
            executables=executables,
            render_config=render_default_config,
            start_wait=WaitLimits(
                timeout=timedelta(seconds=repairs.verify_timeout_seconds),
                interval=timedelta(seconds=repairs.verify_interval_seconds),
            ),
        ),
        uninstall_agent=UninstallAgent(
            workspace=workspace,
            registry=startup_registry,
            guard=instance_guard,
            process_reader=process_reader,
            controller=process_controller,
            clock=clock,
            locations=locations,
            executables=executables,
            own_pid=os.getpid(),
            limits=WaitLimits(
                timeout=timedelta(seconds=repairs.verify_timeout_seconds),
                interval=timedelta(seconds=repairs.verify_interval_seconds),
            ),
            release_storage=database.close,
        ),
        init_config=InitConfig(
            workspace=workspace, locations=locations, render_config=render_default_config
        ),
        describe_config=partial(render_effective_config, settings),
        closers=tuple(closers),
    )


def _diagnosis_policy(
    settings: Settings,
    pressure: PressureThresholds,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
) -> DiagnosisPolicy:
    diagnosis, classifiers = settings.diagnosis, settings.classifiers
    return DiagnosisPolicy(
        pressure=pressure,
        hogs=HogThresholds(
            cpu_percent=diagnosis.hog_cpu_percent, memory_percent=diagnosis.hog_memory_percent
        ),
        stale_after=timedelta(minutes=diagnosis.stale_process_age_minutes),
        classifier=DevelopmentClassifier(
            process_names=classifiers.development_process_names,
            command_markers=classifiers.development_command_markers,
        ),
        protection=protection,
        ancestry=ancestry,
        max_command_line=settings.incidents.max_command_line,
    )


def _diagnosis_limits(settings: Settings, measurement: HealthLimits) -> DiagnosisLimits:
    diagnosis = settings.diagnosis
    return DiagnosisLimits(
        default_lookback=timedelta(minutes=diagnosis.default_lookback_minutes),
        max_lookback=timedelta(minutes=diagnosis.max_lookback_minutes),
        max_incidents=diagnosis.max_incidents,
        max_findings=diagnosis.max_findings,
        max_hogs=diagnosis.max_hogs,
        max_stale_trees=diagnosis.max_stale_trees,
        max_hung_processes=diagnosis.max_hung_processes,
        max_incidents_per_contributor=diagnosis.max_incidents_per_contributor,
        finding=FindingLimits(
            max_evidence=diagnosis.max_evidence_per_finding,
            max_affected_processes=diagnosis.max_affected_processes,
        ),
        measurement=measurement,
    )


def utf8_text(stream: TextIO) -> TextIO:
    """Make an entry point's standard stream write UTF-8, escaping what it cannot carry.

    Redirected, Python 3.13 on Windows writes the ANSI code page (cp1250, cp1252, ...),
    which cannot represent most of Unicode; process names, command lines and window
    titles are arbitrary Unicode and may even hold lone surrogates. Consoles are
    unaffected (Python writes them as UTF-16).
    """
    if isinstance(stream, io.TextIOWrapper):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    return stream


def try_compose(
    program: str,
    *,
    environ: Mapping[str, str],
    log_stream: TextIO,
    error_stream: TextIO,
    log_file: Path | None = None,
) -> Container | None:
    """Compose for an entry point, reporting configuration and storage errors instead of raising.

    Returns ``None`` after writing an actionable diagnostic to *error_stream*; the caller
    should exit with :data:`EXIT_CONFIGURATION_ERROR`.
    """
    try:
        return compose(environ=environ, log_stream=log_stream, log_file=log_file)
    except ConfigurationError as exc:
        error_stream.write(f"{program}: configuration error\n{exc}\n")
        return None
    except DatabaseOpenError as exc:
        error_stream.write(f"{program}: storage error\n{exc}\n")
        return None
