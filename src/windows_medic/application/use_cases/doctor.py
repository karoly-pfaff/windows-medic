"""``windows-medic doctor``: verify the installation without changing anything."""

from dataclasses import dataclass
from enum import StrEnum

from windows_medic.application.operations import (
    Executables,
    Locations,
    Runtime,
    agent_processes,
)
from windows_medic.application.ports.instance_guard import InstanceGuard
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.ports.startup_registry import Registration, StartupRegistry
from windows_medic.application.ports.workspace import Workspace
from windows_medic.application.use_cases.list_recent_incidents import ListRecentIncidents
from windows_medic.domain.errors import IncidentStoreError, ObservationError


class CheckStatus(StrEnum):
    OK = "ok"
    WARNING = "warning"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    status: CheckStatus
    detail: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]

    @property
    def healthy(self) -> bool:
        return all(check.status is not CheckStatus.FAILED for check in self.checks)


class RunDoctor:
    def __init__(
        self,
        *,
        workspace: Workspace,
        startup: StartupRegistry,
        guard: InstanceGuard,
        process_reader: ProcessReader,
        incidents: ListRecentIncidents,
        locations: Locations,
        executables: Executables,
        runtime: Runtime,
        high_risk_enabled: bool = False,
    ) -> None:
        self._workspace = workspace
        self._startup = startup
        self._guard = guard
        self._process_reader = process_reader
        self._incidents = incidents
        self._locations = locations
        self._executables = executables
        self._runtime = runtime
        self._high_risk_enabled = high_risk_enabled

    def execute(self) -> DoctorReport:
        return DoctorReport(
            (
                self._runtime_check(),
                self._configuration_check(),
                self._data_directory_check(),
                self._database_check(),
                self._executables_check(),
                self._startup_check(),
                self._agent_check(),
                self._elevation_check(),
            )
        )

    def _elevation_check(self) -> DoctorCheck:
        if not self._high_risk_enabled:
            return DoctorCheck(
                "elevation", CheckStatus.OK, "high-risk repairs disabled; nothing is elevated"
            )
        # The helper lives in the user's own environment: same-user code could replace it
        # before the UAC prompt runs it as administrator (docs/safety-review.md).
        return DoctorCheck(
            "elevation",
            CheckStatus.WARNING,
            "high-risk repairs enabled: `restart-component dwm` runs "
            f"{self._executables.elevated_helper} as administrator through UAC; that file and "
            "its Python environment are writable by your account, so only approve a UAC "
            "prompt you started yourself",
        )

    def _runtime_check(self) -> DoctorCheck:
        runtime = self._runtime
        return DoctorCheck(
            "runtime",
            CheckStatus.OK,
            f"windows-medic {runtime.package_version} on Python {runtime.python_version} "
            f"({runtime.python_executable})",
        )

    def _configuration_check(self) -> DoctorCheck:
        locations = self._locations
        if locations.config_present:
            return DoctorCheck("configuration", CheckStatus.OK, f"loaded {locations.config_file}")
        return DoctorCheck(
            "configuration",
            CheckStatus.OK,
            f"built-in defaults (no {locations.config_file}; create one with "
            "`windows-medic config init`)",
        )

    def _data_directory_check(self) -> DoctorCheck:
        data_dir = self._locations.data_dir
        problem = self._workspace.probe_writable(data_dir)
        if problem is None:
            return DoctorCheck("data_directory", CheckStatus.OK, f"{data_dir} is writable")
        return DoctorCheck("data_directory", CheckStatus.FAILED, problem)

    def _database_check(self) -> DoctorCheck:
        database = self._locations.database
        size = self._workspace.size(database)
        try:
            self._incidents.execute(1)
        except IncidentStoreError as exc:
            return DoctorCheck("database", CheckStatus.FAILED, f"{database}: {exc}")
        return DoctorCheck(
            "database",
            CheckStatus.OK,
            f"{database} ({_mebibytes(size)}) opens and answers queries",
        )

    def _executables_check(self) -> DoctorCheck:
        missing = [path for path in self._executables.all() if not self._workspace.exists(path)]
        if missing:
            listed = ", ".join(str(path) for path in missing)
            return DoctorCheck(
                "executables",
                CheckStatus.FAILED,
                f"missing: {listed} (run `uv sync --all-groups`)",
            )
        return DoctorCheck(
            "executables",
            CheckStatus.OK,
            f"all console scripts present in {self._executables.cli.parent}",
        )

    def _startup_check(self) -> DoctorCheck:
        state = self._startup.state()
        if state.registration is Registration.REGISTERED:
            return DoctorCheck("startup", CheckStatus.OK, f"logon task runs: {state.command}")
        if state.registration is Registration.NOT_REGISTERED:
            return DoctorCheck(
                "startup",
                CheckStatus.WARNING,
                "no logon task; run `windows-medic install-agent` to start the agent at logon",
            )
        return DoctorCheck(
            "startup", CheckStatus.WARNING, f"logon task state unknown: {state.detail}"
        )

    def _agent_check(self) -> DoctorCheck:
        lease = self._guard.try_acquire()
        if lease is not None:
            lease.release()
        try:
            running = agent_processes(self._process_reader.snapshot().processes, self._executables)
        except ObservationError as exc:
            return DoctorCheck("agent", CheckStatus.FAILED, f"process inventory failed: {exc}")
        pids = ", ".join(str(o.identity.pid) for o in running)
        if lease is None:
            return DoctorCheck(
                "agent", CheckStatus.OK, f"running (single-instance lock held; pids {pids or '?'})"
            )
        if running:
            return DoctorCheck(
                "agent",
                CheckStatus.WARNING,
                f"agent processes found (pids {pids}) but the single-instance lock is free",
            )
        return DoctorCheck(
            "agent",
            CheckStatus.WARNING,
            "not running; `windows-medic install-agent` registers and starts it",
        )


def _mebibytes(size: int | None) -> str:
    if size is None:
        return "absent"
    return f"{size / (1024 * 1024):.1f} MiB"
