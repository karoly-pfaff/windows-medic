"""Deterministic fakes for application ports. No OS access, no real time."""

from collections import deque
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from pathlib import Path, PurePath

from windows_medic.application.ports.startup_registry import Registration, StartupState
from windows_medic.domain.errors import (
    IncidentStoreError,
    ObservationError,
    RepairAuditError,
    StartupRegistrationError,
    WorkspaceError,
)
from windows_medic.domain.models.component import StartAttempt, WindowsComponent
from windows_medic.domain.models.elevation import (
    ElevatedOutcome,
    ElevatedRequest,
    ElevatedResult,
)
from windows_medic.domain.models.gui import HungWindow
from windows_medic.domain.models.incident import (
    Incident,
    IncidentSummary,
    interrupt_incident,
    summarise,
)
from windows_medic.domain.models.network import ListeningEndpoint
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.repair import (
    RepairRecord,
    TerminationAttempt,
    TerminationOutcome,
)
from windows_medic.domain.models.samples import ProcessSnapshot, SystemObservation


class FakeClock:
    """Advances only when told to; records every sleep so tests can assert on it."""

    def __init__(self, start: datetime) -> None:
        self.current = start
        self.sleeps: list[float] = []

    def now(self) -> datetime:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.current += timedelta(seconds=seconds)


class FakeSystemReader:
    """Returns scripted observations in order; raises if asked for more than scripted."""

    def __init__(self, *observations: SystemObservation) -> None:
        self._pending = deque(observations)
        self.calls = 0

    def snapshot(self) -> SystemObservation:
        self.calls += 1
        return self._pending.popleft()


class FakeProcessReader:
    """Returns scripted snapshots in order.

    ``get`` resolves against ``lookup`` when given (to script a state that changed after the
    last snapshot), otherwise against the latest snapshot.
    """

    def __init__(self, *snapshots: ProcessSnapshot, lookup: ProcessSnapshot | None = None) -> None:
        self._pending = deque(snapshots)
        self._latest: ProcessSnapshot | None = None
        self._lookup = lookup
        self.calls = 0
        self.lookups: list[ProcessIdentity] = []
        self.fail_next: str | None = None

    def snapshot(self) -> ProcessSnapshot:
        self.calls += 1
        if self.fail_next is not None:
            reason, self.fail_next = self.fail_next, None
            raise ObservationError(reason)
        self._latest = self._pending.popleft()
        return self._latest

    def get(self, identity: ProcessIdentity) -> ProcessObservation | None:
        self.lookups.append(identity)
        source = self._lookup if self._lookup is not None else self._latest
        if source is None:
            return None
        return next((p for p in source.processes if p.identity == identity), None)


class FakeNetworkReader:
    """Returns a scripted listener table."""

    def __init__(self, *listeners: ListeningEndpoint) -> None:
        self._listeners = tuple(listeners)
        self.calls = 0

    def tcp_listeners(self) -> tuple[ListeningEndpoint, ...]:
        self.calls += 1
        return self._listeners


class FakeIncidentRepository:
    """In-memory incident store; can be scripted to fail on chosen save calls."""

    def __init__(self) -> None:
        self.incidents: dict[str, Incident] = {}
        self.saves = 0
        self.recent_calls: list[int] = []
        self.active_since_calls: list[tuple[datetime, int]] = []
        self.fail_saves: set[int] = set()
        self.fail_reads: str | None = None
        self.purged_before: list[datetime] = []

    def save(self, incident: Incident) -> None:
        self.saves += 1
        if self.saves in self.fail_saves:
            raise IncidentStoreError("database is locked")
        self.incidents[incident.id] = incident

    def get(self, incident_id: str) -> Incident | None:
        return self.incidents.get(incident_id)

    def recent(self, *, limit: int) -> tuple[IncidentSummary, ...]:
        self.recent_calls.append(limit)
        if self.fail_reads is not None:
            raise IncidentStoreError(self.fail_reads)
        ordered = sorted(self.incidents.values(), key=lambda i: i.started_at, reverse=True)
        return tuple(summarise(i) for i in ordered[:limit])

    def active_since(self, cutoff: datetime, *, limit: int) -> tuple[Incident, ...]:
        self.active_since_calls.append((cutoff, limit))
        active = [
            i for i in self.incidents.values() if i.closed_at is None or i.closed_at >= cutoff
        ]
        active.sort(key=lambda i: (i.started_at, i.id), reverse=True)
        return tuple(active[:limit])

    def interrupt_unclosed(self) -> tuple[str, ...]:
        """Ends each unclosed incident at its trigger time (the fake keeps no write times)."""
        if self.fail_reads is not None:
            raise IncidentStoreError(self.fail_reads)
        unclosed = [i for i in self.incidents.values() if i.closed_at is None]
        for incident in unclosed:
            self.incidents[incident.id] = interrupt_incident(incident, incident.triggered_at)
        return tuple(i.id for i in unclosed)

    def purge_older_than(self, cutoff: datetime) -> int:
        self.purged_before.append(cutoff)
        stale = [i for i in self.incidents.values() if (i.closed_at or i.started_at) < cutoff]
        for incident in stale:
            del self.incidents[incident.id]
        return len(stale)


class FakeHungWindowReader:
    """Returns a scripted list of hung windows."""

    def __init__(self, *windows: HungWindow) -> None:
        self._windows = tuple(windows)
        self.calls = 0

    def hung_windows(self) -> tuple[HungWindow, ...]:
        self.calls += 1
        return self._windows


class FakeProcessWorld:
    """A mutable live process table shared by a ProcessReader and a ProcessController fake.

    Terminating a process removes it from the table, unless it is scripted to be
    ``denied`` (access denied, stays alive), ``failing`` (an OS error, stays alive) or
    ``stubborn`` (signalled, but only gone at the n-th snapshot after the signal). A
    process scripted in ``spawns`` creates its child the moment it is signalled, to
    simulate a parent respawning work while a tree is being torn down; one listed in
    ``vanish_after_plan`` exits right after the next snapshot is taken.
    """

    def __init__(self, clock: FakeClock, *processes: ProcessObservation) -> None:
        self.clock = clock
        self.live: dict[ProcessIdentity, ProcessObservation] = {p.identity: p for p in processes}
        self.denied: set[ProcessIdentity] = set()
        self.failing: dict[ProcessIdentity, str] = {}
        self.stubborn: dict[ProcessIdentity, int] = {}
        self.spawns: dict[ProcessIdentity, ProcessObservation] = {}
        self.vanish_after_plan: set[ProcessIdentity] = set()
        self._dying: dict[ProcessIdentity, int] = {}
        self.terminations: list[ProcessIdentity] = []
        self.snapshots = 0
        # From this snapshot number on, every read fails (enumeration broke mid-repair).
        self.fail_from_snapshot: int | None = None

    def dies_after(self, identity: ProcessIdentity, *, snapshots: int) -> None:
        """Script *identity* (live now or spawned later) to vanish after *snapshots* reads."""
        self._dying[identity] = snapshots

    # -- ProcessReader ---------------------------------------------------------------------

    def snapshot(self) -> ProcessSnapshot:
        self.snapshots += 1
        if self.fail_from_snapshot is not None and self.snapshots >= self.fail_from_snapshot:
            raise ObservationError("process enumeration failed: scripted")
        for identity in list(self._dying):
            self._dying[identity] -= 1
            if self._dying[identity] <= 0:
                del self._dying[identity]
                self.live.pop(identity, None)
        snapshot = ProcessSnapshot(
            observed_at=self.clock.now(), processes=tuple(self.live.values()), skipped_count=0
        )
        for identity in self.vanish_after_plan:
            self.live.pop(identity, None)
        self.vanish_after_plan.clear()
        return snapshot

    def get(self, identity: ProcessIdentity) -> ProcessObservation | None:
        return self.live.get(identity)

    # -- ProcessController -----------------------------------------------------------------

    def terminate(self, identity: ProcessIdentity) -> TerminationAttempt:
        self.terminations.append(identity)
        current = next((i for i in self.live if i.pid == identity.pid), None)
        if current is None:
            return TerminationAttempt(TerminationOutcome.ALREADY_GONE)
        if current != identity:
            return TerminationAttempt(TerminationOutcome.IDENTITY_MISMATCH)
        if identity in self.denied:
            return TerminationAttempt(TerminationOutcome.ACCESS_DENIED, "access is denied")
        if identity in self.failing:
            return TerminationAttempt(TerminationOutcome.ERROR, self.failing[identity])
        spawned = self.spawns.pop(identity, None)
        if spawned is not None:
            self.live[spawned.identity] = spawned
        if identity in self.stubborn:
            self._dying[identity] = self.stubborn.pop(identity)
        else:
            del self.live[identity]
        return TerminationAttempt(TerminationOutcome.SIGNALLED)


class FakeWorldNetworkReader:
    """A listener table showing only endpoints whose owner is still alive in a world.

    ``later`` replaces the scripted table after the first read, to script a listener
    that appears between a plan and its verification.
    """

    def __init__(
        self,
        world: FakeProcessWorld,
        *listeners: ListeningEndpoint,
        later: tuple[ListeningEndpoint, ...] | None = None,
    ) -> None:
        self._world = world
        self._listeners = listeners
        self._later = later
        self.calls = 0

    def tcp_listeners(self) -> tuple[ListeningEndpoint, ...]:
        self.calls += 1
        table = self._listeners if self.calls == 1 or self._later is None else self._later
        live_pids = {i.pid for i in self._world.live}
        return tuple(e for e in table if e.owner_pid is None or e.owner_pid in live_pids)


class FakeRepairAudit:
    """In-memory repair audit; can be scripted to fail on chosen save calls."""

    def __init__(self) -> None:
        self.records: dict[str, RepairRecord] = {}
        self.saves: list[RepairRecord] = []
        self.fail_saves: set[int] = set()
        self.fail_reads: str | None = None
        self.purged_before: list[datetime] = []

    def save(self, record: RepairRecord) -> None:
        if len(self.saves) + 1 in self.fail_saves:
            self.saves.append(record)
            raise RepairAuditError("database is locked")
        self.saves.append(record)
        self.records[record.id] = record

    def get(self, repair_id: str) -> RepairRecord | None:
        return self.records.get(repair_id)

    def recent(self, *, limit: int) -> tuple[RepairRecord, ...]:
        if self.fail_reads is not None:
            raise RepairAuditError(self.fail_reads)
        ordered = sorted(self.records.values(), key=lambda r: (r.requested_at, r.id), reverse=True)
        return tuple(ordered[:limit])

    def purge_older_than(self, cutoff: datetime) -> int:
        self.purged_before.append(cutoff)
        stale = [r for r in self.records.values() if r.requested_at < cutoff]
        for record in stale:
            del self.records[record.id]
        return len(stale)


class FakeElevatedHelper:
    """Runs elevated requests against a FakeProcessWorld, or returns a scripted result."""

    def __init__(self, world: FakeProcessWorld, *, scripted: ElevatedResult | None = None) -> None:
        self._world = world
        self._scripted = scripted
        self.requests: list[ElevatedRequest] = []

    def run(self, request: ElevatedRequest) -> ElevatedResult:
        self.requests.append(request)
        if self._scripted is not None:
            return self._scripted
        return ElevatedResult(ElevatedOutcome.COMPLETED, self._world.terminate(request.target))


class FakeComponentController:
    """Starts a scripted replacement process into a FakeProcessWorld."""

    def __init__(
        self, world: FakeProcessWorld, *, replacement: ProcessObservation | None = None
    ) -> None:
        self._world = world
        self._replacement = replacement
        self.started: list[WindowsComponent] = []

    def start(self, component: WindowsComponent) -> StartAttempt:
        self.started.append(component)
        if self._replacement is None:
            return StartAttempt(None, "start failed: file not found")
        self._world.live[self._replacement.identity] = self._replacement
        return StartAttempt(self._replacement.identity.pid)


class FakeWorkspace:
    """An in-memory data directory: directories, files with sizes, scripted failures."""

    def __init__(self, *, unwritable: str | None = None) -> None:
        self.directories: set[PurePath] = set()
        self.files: dict[PurePath, str] = {}
        self.unwritable = unwritable
        self.removed: list[PurePath] = []
        self.fail_removal: str | None = None

    def ensure_directory(self, path: PurePath) -> None:
        if self.unwritable is not None:
            raise WorkspaceError(f"cannot create {path}: {self.unwritable}")
        self.directories.add(path)

    def probe_writable(self, directory: PurePath) -> str | None:
        if self.unwritable is not None:
            return f"{directory}: {self.unwritable}"
        if directory not in self.directories:
            return f"{directory}: no such directory"
        return None

    def exists(self, path: PurePath) -> bool:
        return path in self.files or path in self.directories

    def size(self, path: PurePath) -> int | None:
        text = self.files.get(path)
        return None if text is None else len(text.encode("utf-8"))

    def write_text(self, path: PurePath, text: str, *, overwrite: bool) -> None:
        if self.unwritable is not None:
            raise WorkspaceError(f"cannot write {path}: {self.unwritable}")
        if path in self.files and not overwrite:
            raise WorkspaceError(f"{path} already exists (use --force to overwrite)")
        self.files[path] = text

    def children(self, directory: PurePath) -> tuple[Path, ...]:
        entries = {f for f in self.files if f.parent == directory}
        entries |= {d for d in self.directories if d.parent == directory and d != directory}
        return tuple(sorted(Path(entry) for entry in entries))

    def remove_file(self, path: PurePath) -> None:
        if self.fail_removal is not None:
            raise WorkspaceError(f"cannot remove {path}: {self.fail_removal}")
        if self.files.pop(path, None) is not None:
            self.removed.append(path)

    def remove_empty_directory(self, path: PurePath) -> bool:
        if path not in self.directories:
            return True
        if self.children(path):
            return False
        self.directories.discard(path)
        self.removed.append(path)
        return True


class FakeStartupRegistry:
    """Remembers one registered command; ``broken`` makes every mutation fail."""

    def __init__(self, *, command: Sequence[str] | None = None, broken: str | None = None) -> None:
        self.command: tuple[str, ...] | None = tuple(command) if command is not None else None
        self.broken = broken
        self.runs = 0
        self.unknown: str | None = None
        # What the task does when run: e.g. an agent that takes its instance lock.
        self.on_run: Callable[[], None] | None = None

    def register(self, command: Sequence[str]) -> None:
        if self.broken is not None:
            raise StartupRegistrationError(self.broken)
        self.command = tuple(command)

    def unregister(self) -> bool:
        if self.broken is not None:
            raise StartupRegistrationError(self.broken)
        had = self.command is not None
        self.command = None
        return had

    def state(self) -> StartupState:
        if self.unknown is not None:
            return StartupState(Registration.UNKNOWN, detail=self.unknown)
        if self.command is None:
            return StartupState(Registration.NOT_REGISTERED, detail="no such task")
        return StartupState(Registration.REGISTERED, command=" ".join(self.command))

    def run_now(self) -> None:
        if self.broken is not None:
            raise StartupRegistrationError(self.broken)
        if self.command is None:
            raise StartupRegistrationError("no such task")
        self.runs += 1
        if self.on_run is not None:
            self.on_run()


class FakeLease:
    def __init__(self, guard: "FakeInstanceGuard") -> None:
        self._guard = guard
        self.released = False

    def release(self) -> None:
        self.released = True
        self._guard.held = False


class FakeInstanceGuard:
    """A lock that is free unless ``held``; acquiring it marks it held until released."""

    def __init__(self, *, held: bool = False) -> None:
        self.held = held
        self.attempts = 0

    def try_acquire(self) -> FakeLease | None:
        self.attempts += 1
        if self.held:
            return None
        self.held = True
        return FakeLease(self)
