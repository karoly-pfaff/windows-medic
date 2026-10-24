"""A fully wired Container over fakes, for interface tests."""

from datetime import timedelta
from pathlib import Path

from tests.builders import GIB, T0, process, process_snapshot, system
from tests.fakes import (
    FakeClock,
    FakeComponentController,
    FakeElevatedHelper,
    FakeHungWindowReader,
    FakeIncidentRepository,
    FakeInstanceGuard,
    FakeNetworkReader,
    FakeProcessReader,
    FakeProcessWorld,
    FakeRepairAudit,
    FakeStartupRegistry,
    FakeSystemReader,
    FakeWorkspace,
)
from windows_medic.application.operations import Executables, Locations, Runtime
from windows_medic.application.ports.network_reader import NetworkReader
from windows_medic.application.ports.process_controller import ProcessController
from windows_medic.application.ports.process_reader import ProcessReader
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
from windows_medic.domain.models.samples import ProcessSnapshot
from windows_medic.domain.policies.finding_assembly import FindingLimits
from windows_medic.domain.policies.pressure import PressureThresholds
from windows_medic.domain.policies.process_classification import DevelopmentClassifier
from windows_medic.domain.policies.protection import ProtectionPolicy
from windows_medic.domain.policies.resource_hogs import HogThresholds
from windows_medic.domain.policies.risk_markers import AncestryPolicy
from windows_medic.infrastructure.config.settings import load_settings
from windows_medic_root.container import Container

T1 = T0 + timedelta(seconds=1)

DATA_DIR = Path("C:/wm")
SCRIPTS_DIR = Path("C:/venv/Scripts")
LOCATIONS = Locations(
    data_dir=DATA_DIR,
    config_file=DATA_DIR / "config.toml",
    config_present=False,
    database=DATA_DIR / "incidents.sqlite3",
    log_dir=DATA_DIR / "logs",
    log_file=DATA_DIR / "logs" / "windows-medic-agent.log",
    elevated_dir=DATA_DIR / "elevated",
)
EXECUTABLES = Executables(
    cli=SCRIPTS_DIR / "windows-medic.exe",
    agent=SCRIPTS_DIR / "windows-medic-agent.exe",
    agent_gui=SCRIPTS_DIR / "windows-medic-agentw.exe",
    mcp_server=SCRIPTS_DIR / "windows-medic-mcp.exe",
    elevated_helper=SCRIPTS_DIR / "windows-medic-elevated.exe",
)
RUNTIME = Runtime("0.1.0", "3.13.7", SCRIPTS_DIR / "python.exe")
DEFAULT_CONFIG = "# Windows Medic configuration.\n"

PROTECTION = ProtectionPolicy(
    own_pid=4242,
    windows_medic_markers=("windows-medic", "windows_medic"),
    user_protected_names=(),
    windows_directory="C:\\Windows",
)
ANCESTRY = AncestryPolicy(
    claude_markers=("claude",), terminal_process_names=("windowsterminal.exe", "pwsh.exe")
)
THRESHOLDS = PressureThresholds(
    cpu_percent=90.0, memory_percent=90.0, memory_available_floor_bytes=int(1.5 * GIB)
)
DIAGNOSIS_POLICY = DiagnosisPolicy(
    pressure=THRESHOLDS,
    hogs=HogThresholds(cpu_percent=10.0, memory_percent=10.0),
    stale_after=timedelta(minutes=30),
    classifier=DevelopmentClassifier(
        process_names=("node.exe", "esbuild.exe", "python.exe"), command_markers=("vite",)
    ),
    protection=PROTECTION,
    ancestry=ANCESTRY,
    max_command_line=200,
)
REPAIR_LIMITS = RepairLimits(
    verify_timeout=timedelta(seconds=2),
    verify_interval=timedelta(milliseconds=100),
    max_tree_members=20,
)
DIAGNOSIS_LIMITS = DiagnosisLimits(
    default_lookback=timedelta(minutes=30),
    max_lookback=timedelta(hours=4),
    max_incidents=5,
    max_findings=6,
    max_hogs=3,
    max_stale_trees=3,
    max_hung_processes=3,
    max_incidents_per_contributor=3,
    finding=FindingLimits(max_evidence=6, max_affected_processes=4),
    measurement=HealthLimits(measurement_window_seconds=1.0, top_contributors=5),
)


def default_snapshots() -> tuple[ProcessSnapshot, ProcessSnapshot]:
    before = process_snapshot(process(10, name="node.exe", cpu_time_seconds=1.0))
    after = process_snapshot(
        process(10, name="node.exe", observed_at=T1, cpu_time_seconds=3.0), observed_at=T1
    )
    return before, after


def fake_container(
    *,
    process_reader: ProcessReader | None = None,
    network_reader: NetworkReader | None = None,
    incident_repository: FakeIncidentRepository | None = None,
    hung_window_reader: FakeHungWindowReader | None = None,
    process_controller: ProcessController | None = None,
    repair_audit: FakeRepairAudit | None = None,
    high_risk_enabled: bool = False,
    workspace: FakeWorkspace | None = None,
    startup_registry: FakeStartupRegistry | None = None,
    instance_guard: FakeInstanceGuard | None = None,
) -> Container:
    settings = load_settings(environ={"WINDOWS_MEDIC_DATA_DIR": str(DATA_DIR)})
    clock = FakeClock(T0)
    system_reader = FakeSystemReader(
        system(observed_at=T0), system(observed_at=T1, busy_seconds=1002.0, total_seconds=10_008.0)
    )
    reader = (
        process_reader if process_reader is not None else FakeProcessReader(*default_snapshots())
    )
    network = network_reader if network_reader is not None else FakeNetworkReader()
    incidents = incident_repository if incident_repository is not None else FakeIncidentRepository()
    hung = hung_window_reader if hung_window_reader is not None else FakeHungWindowReader()
    controller = (
        process_controller
        if process_controller is not None
        else FakeProcessWorld(clock)  # nothing to terminate unless a world is shared
    )
    audit = repair_audit if repair_audit is not None else FakeRepairAudit()
    world = process_controller if isinstance(process_controller, FakeProcessWorld) else None
    component_world = world if world is not None else FakeProcessWorld(clock)
    components = FakeComponentController(component_world)
    elevated = FakeElevatedHelper(component_world)
    limits = InspectionLimits(max_ancestors=5, max_descendants=5, max_port_owners=3)
    inspect_port = InspectPort(
        process_reader=reader,
        network_reader=network,
        protection=PROTECTION,
        ancestry=ANCESTRY,
        limits=limits,
    )
    files = workspace if workspace is not None else FakeWorkspace()
    registry = startup_registry if startup_registry is not None else FakeStartupRegistry()
    guard = instance_guard if instance_guard is not None else FakeInstanceGuard()
    list_incidents = ListRecentIncidents(incidents, IncidentListLimits(max_limit=20))
    list_repairs = ListRecentRepairs(audit, RepairListLimits(max_limit=20))
    trail = RepairAuditTrail(audit=audit, clock=clock, retention=timedelta(days=30))
    executor = RepairExecutor(
        process_reader=reader,
        controller=controller,
        trail=trail,
        protection=PROTECTION,
        ancestry=ANCESTRY,
        limits=REPAIR_LIMITS,
    )
    return Container(
        settings=settings,
        clock=clock,
        system_reader=system_reader,
        process_reader=reader,
        network_reader=network,
        incident_repository=incidents,
        repair_audit=audit,
        process_controller=controller,
        component_controller=components,
        elevated_helper=elevated,
        hung_window_reader=hung,
        protection_policy=PROTECTION,
        ancestry_policy=ANCESTRY,
        pressure_thresholds=THRESHOLDS,
        get_system_health=GetSystemHealth(
            system_reader=system_reader,
            process_reader=reader,
            clock=clock,
            limits=HealthLimits(measurement_window_seconds=1.0, top_contributors=5),
        ),
        inspect_process=InspectProcess(
            process_reader=reader, protection=PROTECTION, ancestry=ANCESTRY, limits=limits
        ),
        inspect_port=inspect_port,
        list_recent_incidents=list_incidents,
        diagnose_slowdown=DiagnoseSlowdown(
            system_reader=system_reader,
            process_reader=reader,
            incident_repository=incidents,
            hung_window_reader=hung,
            clock=clock,
            policy=DIAGNOSIS_POLICY,
            limits=DIAGNOSIS_LIMITS,
        ),
        terminate_process=TerminateProcess(executor=executor),
        clear_port=ClearPort(inspect_port=inspect_port, network_reader=network, executor=executor),
        list_recent_repairs=list_repairs,
        restart_windows_component=RestartWindowsComponent(
            process_reader=reader,
            controller=controller,
            component_controller=components,
            elevated_helper=elevated,
            trail=trail,
            own_pid=PROTECTION.own_pid or 0,
            high_risk_enabled=high_risk_enabled,
            limits=ComponentRepairLimits(
                verify_timeout=timedelta(seconds=2),
                verify_interval=timedelta(milliseconds=100),
                auto_restart_wait=timedelta(seconds=1),
            ),
        ),
        workspace=files,
        startup_registry=registry,
        instance_guard=guard,
        locations=LOCATIONS,
        executables=EXECUTABLES,
        runtime=RUNTIME,
        run_doctor=RunDoctor(
            workspace=files,
            startup=registry,
            guard=guard,
            process_reader=reader,
            incidents=list_incidents,
            locations=LOCATIONS,
            executables=EXECUTABLES,
            runtime=RUNTIME,
        ),
        show_status=ShowStatus(
            startup=registry,
            guard=guard,
            process_reader=reader,
            incidents=list_incidents,
            repairs=list_repairs,
            locations=LOCATIONS,
            executables=EXECUTABLES,
            runtime=RUNTIME,
        ),
        install_agent=InstallAgent(
            workspace=files,
            registry=registry,
            guard=guard,
            clock=clock,
            locations=LOCATIONS,
            executables=EXECUTABLES,
            render_config=lambda: DEFAULT_CONFIG,
            start_wait=WaitLimits(
                timeout=timedelta(seconds=2), interval=timedelta(milliseconds=100)
            ),
        ),
        uninstall_agent=UninstallAgent(
            workspace=files,
            registry=registry,
            guard=guard,
            process_reader=reader,
            controller=controller,
            clock=clock,
            locations=LOCATIONS,
            executables=EXECUTABLES,
            own_pid=PROTECTION.own_pid or 0,
            limits=WaitLimits(timeout=timedelta(seconds=2), interval=timedelta(milliseconds=100)),
            release_storage=lambda: None,
        ),
        init_config=InitConfig(
            workspace=files, locations=LOCATIONS, render_config=lambda: DEFAULT_CONFIG
        ),
        describe_config=lambda: "[pressure]\ncpu_percent = 90.0\n",
    )
