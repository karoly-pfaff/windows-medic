"""``windows-medic status``: where things are and what is running. Read-only."""

from dataclasses import dataclass

from windows_medic.application.operations import Executables, Locations, Runtime, agent_processes
from windows_medic.application.ports.instance_guard import InstanceGuard
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.ports.startup_registry import StartupRegistry, StartupState
from windows_medic.application.use_cases.list_recent_incidents import ListRecentIncidents
from windows_medic.application.use_cases.list_recent_repairs import ListRecentRepairs
from windows_medic.domain.errors import IncidentStoreError, ObservationError, RepairAuditError
from windows_medic.domain.models.incident import IncidentSummary
from windows_medic.domain.models.repair import RepairRecord


@dataclass(frozen=True, slots=True)
class AgentState:
    running: bool
    pids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class StatusReport:
    runtime: Runtime
    locations: Locations
    executables: Executables
    agent: AgentState
    startup: StartupState
    latest_incident: IncidentSummary | None
    latest_repair: RepairRecord | None
    store_problem: str | None


class ShowStatus:
    def __init__(
        self,
        *,
        startup: StartupRegistry,
        guard: InstanceGuard,
        process_reader: ProcessReader,
        incidents: ListRecentIncidents,
        repairs: ListRecentRepairs,
        locations: Locations,
        executables: Executables,
        runtime: Runtime,
    ) -> None:
        self._startup = startup
        self._guard = guard
        self._process_reader = process_reader
        self._incidents = incidents
        self._repairs = repairs
        self._locations = locations
        self._executables = executables
        self._runtime = runtime

    def execute(self) -> StatusReport:
        lease = self._guard.try_acquire()
        if lease is not None:
            lease.release()
        pids: tuple[int, ...] = ()
        try:
            pids = tuple(
                o.identity.pid
                for o in agent_processes(
                    self._process_reader.snapshot().processes, self._executables
                )
            )
        except ObservationError:
            pids = ()
        latest_incident: IncidentSummary | None = None
        latest_repair: RepairRecord | None = None
        store_problem: str | None = None
        try:
            incidents = self._incidents.execute(1)
            repairs = self._repairs.execute(1)
            latest_incident = incidents[0] if incidents else None
            latest_repair = repairs[0] if repairs else None
        except (IncidentStoreError, RepairAuditError) as exc:
            store_problem = str(exc)
        return StatusReport(
            runtime=self._runtime,
            locations=self._locations,
            executables=self._executables,
            agent=AgentState(running=lease is None, pids=pids),
            startup=self._startup.state(),
            latest_incident=latest_incident,
            latest_repair=latest_repair,
            store_problem=store_problem,
        )
