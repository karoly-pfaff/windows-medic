"""``install-agent`` / ``uninstall-agent``: the logon registration and the data layout.

Installation is idempotent: it creates what is missing, keeps an existing configuration
and replaces the registration. Uninstallation removes the registration; the user's
evidence (database, logs) survives unless purging is requested explicitly, and purging
refuses to race a running agent.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from windows_medic.application.operations import (
    AGENT_LOG_NAME,
    DATABASE_COMPANION_SUFFIXES,
    ELEVATED_RESULT_PREFIX,
    Executables,
    Locations,
    agent_command,
    agent_processes,
)
from windows_medic.application.ports.clock import Clock
from windows_medic.application.ports.instance_guard import InstanceGuard
from windows_medic.application.ports.process_controller import ProcessController
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.ports.startup_registry import StartupRegistry, StartupState
from windows_medic.application.ports.workspace import Workspace
from windows_medic.domain.errors import WorkspaceError
from windows_medic.domain.models.process import ProcessIdentity


@dataclass(frozen=True, slots=True)
class InstallReport:
    command: tuple[str, ...]
    config_created: bool
    # True only once the started agent was seen holding its single-instance lock.
    started: bool
    already_running: bool
    startup: StartupState
    start_requested: bool = False


class InstallAgent:
    def __init__(
        self,
        *,
        workspace: Workspace,
        registry: StartupRegistry,
        guard: InstanceGuard,
        clock: Clock,
        locations: Locations,
        executables: Executables,
        render_config: Callable[[], str],
        start_wait: "WaitLimits",
    ) -> None:
        self._workspace = workspace
        self._registry = registry
        self._guard = guard
        self._clock = clock
        self._locations = locations
        self._executables = executables
        self._render_config = render_config
        self._start_wait = start_wait

    def execute(self, *, start_now: bool) -> InstallReport:
        locations = self._locations
        for directory in (locations.data_dir, locations.log_dir, locations.elevated_dir):
            self._workspace.ensure_directory(directory)
        config_created = False
        if not self._workspace.exists(locations.config_file):
            self._workspace.write_text(
                locations.config_file, self._render_config(), overwrite=False
            )
            config_created = True
        command = agent_command(self._executables, locations)
        self._registry.register(command)
        already_running = self._agent_running()
        requested = started = False
        if start_now and not already_running:
            self._registry.run_now()
            requested = True
            started = self._seen_running()
        return InstallReport(
            command=command,
            config_created=config_created,
            started=started,
            already_running=already_running,
            startup=self._registry.state(),
            start_requested=requested,
        )

    def _seen_running(self) -> bool:
        """Task Scheduler accepting the run proves nothing: wait, bounded, for the agent
        to take its lock."""
        deadline = self._clock.now() + self._start_wait.timeout
        while not self._agent_running():
            if self._clock.now() >= deadline:
                return False
            self._clock.sleep(self._start_wait.interval.total_seconds())
        return True

    def _agent_running(self) -> bool:
        lease = self._guard.try_acquire()
        if lease is None:
            return True
        lease.release()
        return False


@dataclass(frozen=True, slots=True)
class WaitLimits:
    """A bounded wait: for signalled agents to disappear (``--stop``), or for a started
    agent to take its single-instance lock (``install-agent``)."""

    timeout: timedelta
    interval: timedelta

    def __post_init__(self) -> None:
        if self.timeout <= timedelta(0):
            raise ValueError("timeout must be positive")
        if self.interval <= timedelta(0):
            raise ValueError("interval must be positive")


@dataclass(frozen=True, slots=True)
class UninstallReport:
    unregistered: bool
    stopped: tuple[ProcessIdentity, ...]
    survivors: tuple[ProcessIdentity, ...]
    purged: bool
    # False when the data directory also held files Windows Medic did not write: those,
    # and the directory, are kept.
    data_dir_removed: bool = False


class UninstallAgent:
    def __init__(
        self,
        *,
        workspace: Workspace,
        registry: StartupRegistry,
        guard: InstanceGuard,
        process_reader: ProcessReader,
        controller: ProcessController,
        clock: Clock,
        locations: Locations,
        executables: Executables,
        own_pid: int,
        limits: WaitLimits,
        release_storage: Callable[[], None],
    ) -> None:
        """*release_storage* closes this process's own handles on the data directory;
        Windows refuses to delete a file that is still open."""
        self._workspace = workspace
        self._registry = registry
        self._guard = guard
        self._process_reader = process_reader
        self._controller = controller
        self._clock = clock
        self._locations = locations
        self._executables = executables
        self._own_pid = own_pid
        self._limits = limits
        self._release_storage = release_storage

    def execute(self, *, stop: bool, purge_data: bool) -> UninstallReport:
        unregistered = self._registry.unregister()
        stopped: tuple[ProcessIdentity, ...] = ()
        survivors: tuple[ProcessIdentity, ...] = ()
        if stop:
            stopped, survivors = self._stop_agents()
        purged = removed = False
        if purge_data:
            self._refuse_purge_while_running(survivors)
            self._release_storage()
            removed = self._purge()
            purged = True
        return UninstallReport(unregistered, stopped, survivors, purged, removed)

    def _purge(self) -> bool:
        """Delete exactly what Windows Medic writes, then each directory only if it is
        empty: a data directory pointed at a folder of the user's own files keeps them."""
        locations = self._locations
        data_dir = locations.data_dir
        owned_files = [
            locations.database,
            *(
                locations.database.with_name(locations.database.name + suffix)
                for suffix in DATABASE_COMPANION_SUFFIXES
            ),
        ]
        if locations.config_file.parent == data_dir:
            owned_files.append(locations.config_file)
        owned_files.extend(
            path
            for path in self._workspace.children(locations.log_dir)
            if path.name.startswith(AGENT_LOG_NAME)  # the log and its rotations
        )
        owned_files.extend(
            path
            for path in self._workspace.children(locations.elevated_dir)
            if path.name.startswith(ELEVATED_RESULT_PREFIX)
        )
        for path in owned_files:
            self._workspace.remove_file(path)
        self._workspace.remove_empty_directory(locations.log_dir)
        self._workspace.remove_empty_directory(locations.elevated_dir)
        return self._workspace.remove_empty_directory(data_dir)

    def _stop_agents(self) -> tuple[tuple[ProcessIdentity, ...], tuple[ProcessIdentity, ...]]:
        """Terminate every agent process by exact identity; wait, bounded, for them to go."""
        targets = [
            o.identity
            for o in agent_processes(self._process_reader.snapshot().processes, self._executables)
            if o.identity.pid != self._own_pid
        ]
        if not targets:
            return (), ()
        for identity in targets:
            self._controller.terminate(identity)
        deadline = self._clock.now() + self._limits.timeout
        while True:
            alive = {o.identity for o in self._process_reader.snapshot().processes}
            if not alive.intersection(targets) or self._clock.now() >= deadline:
                break
            self._clock.sleep(self._limits.interval.total_seconds())
        stopped = tuple(i for i in targets if i not in alive)
        survivors = tuple(i for i in targets if i in alive)
        return stopped, survivors

    def _refuse_purge_while_running(self, survivors: tuple[ProcessIdentity, ...]) -> None:
        if survivors:
            listed = ", ".join(f"pid {i.pid}" for i in survivors)
            raise WorkspaceError(f"not purging data: agent processes still running ({listed})")
        lease = self._guard.try_acquire()
        if lease is None:
            raise WorkspaceError(
                "not purging data: the agent is still running (add --stop or close it first)"
            )
        lease.release()
