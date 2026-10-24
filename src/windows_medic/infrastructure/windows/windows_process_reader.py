""":class:`ProcessReader` for Windows (docs/architecture.md §13).

The inventory comes from one kernel enumeration, so every observation in a snapshot shares
the same instant and identities are exact. Fields that need a process handle (executable
path, command line, username) are read through psutil per process and degrade individually
into explicit ``Unavailable`` reasons; nothing about one process can fail the snapshot. A
process that denies even limited query access is not opened at all: its path is read
without a handle and the rest is ``access_denied`` (psutil learns that slowly, per field).

Handle fields never change for a given identity, so they are cached per identity and read
only once. Transient outcomes (process gone mid-read, OS error) are not cached. The cache is
bounded by the live process table: entries of identities that no longer exist are evicted
on every snapshot.
"""

import threading
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

import psutil

from windows_medic.application.ports.clock import Clock
from windows_medic.domain.errors import ObservationError
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.samples import ProcessSnapshot
from windows_medic.infrastructure.windows.nt_process_enumeration import (
    NtProcessEntry,
    enumerate_processes,
)
from windows_medic.infrastructure.windows.process_access import (
    ProcessGoneError,
    image_path_without_handle,
    may_open_limited,
)


class ProcessInventoryError(ObservationError):
    """The kernel process enumeration itself failed; no snapshot could be taken."""


class _HandleProcess(Protocol):
    """The subset of ``psutil.Process`` needed for per-handle fields."""

    def oneshot(self) -> AbstractContextManager[None]: ...
    def exe(self) -> str: ...
    def cmdline(self) -> list[str]: ...
    def username(self) -> str: ...


@dataclass(frozen=True, slots=True)
class _HandleFields:
    exe_path: Metric[str]
    command_line: Metric[tuple[str, ...]]
    username: Metric[str]

    @property
    def is_stable(self) -> bool:
        """True unless some field failed for a transient reason worth retrying."""
        return not any(
            isinstance(field, Unavailable) and field.reason in _TRANSIENT
            for field in (self.exe_path, self.command_line, self.username)
        )


_GONE = Unavailable(UnavailableReason.PROCESS_GONE)
_DENIED = Unavailable(UnavailableReason.ACCESS_DENIED)
_TRANSIENT = frozenset({UnavailableReason.PROCESS_GONE, UnavailableReason.ERROR})


class WindowsProcessReader:
    """Reads the process inventory: kernel enumeration plus per-handle psutil fields.

    Safe to share between threads (the MCP server runs tools on worker threads): reads that
    touch the handle cache are serialised.
    """

    def __init__(
        self,
        clock: Clock,
        *,
        inventory: Callable[[], list[NtProcessEntry]] = enumerate_processes,
        process: Callable[[int], _HandleProcess] = psutil.Process,
        may_open: Callable[[int], bool] = may_open_limited,
        image_path: Callable[[int], str] = image_path_without_handle,
    ) -> None:
        self._clock = clock
        self._inventory = inventory
        self._process = process
        self._may_open = may_open
        self._image_path = image_path
        self._handle_cache: dict[ProcessIdentity, _HandleFields] = {}
        self._lock = threading.Lock()

    @property
    def cached_identities(self) -> int:
        return len(self._handle_cache)

    def snapshot(self) -> ProcessSnapshot:
        with self._lock:
            observed_at = self._clock.now()
            entries = self._entries()
            observations = tuple(self._observe(entry, observed_at) for entry in entries)
            live = {observation.identity for observation in observations}
            self._handle_cache = {i: f for i, f in self._handle_cache.items() if i in live}
        return ProcessSnapshot(observed_at=observed_at, processes=observations, skipped_count=0)

    def get(self, identity: ProcessIdentity) -> ProcessObservation | None:
        with self._lock:
            observed_at = self._clock.now()
            entry = next((e for e in self._entries() if e.pid == identity.pid), None)
            if entry is None or entry.create_time != identity.create_time:
                return None
            return self._observe(entry, observed_at)

    def _entries(self) -> list[NtProcessEntry]:
        try:
            return self._inventory()
        except OSError as exc:
            raise ProcessInventoryError(f"process enumeration failed: {exc}") from exc

    def _observe(self, entry: NtProcessEntry, observed_at: datetime) -> ProcessObservation:
        identity = ProcessIdentity(entry.pid, entry.create_time)
        handle = self._handle_cache.get(identity)
        if handle is None:
            handle = self._handle_fields(entry.pid)
            if handle.is_stable:
                self._handle_cache[identity] = handle
        return ProcessObservation(
            identity=identity,
            observed_at=observed_at,
            name=entry.image_name,
            exe_path=handle.exe_path,
            command_line=handle.command_line,
            parent_pid=entry.parent_pid,
            username=handle.username,
            session_id=entry.session_id,
            cpu_time_seconds=entry.cpu_time_seconds,
            working_set_bytes=entry.working_set_bytes,
            private_bytes=entry.private_bytes,
            io_read_bytes=entry.io_read_bytes,
            io_write_bytes=entry.io_write_bytes,
            thread_count=entry.thread_count,
            handle_count=entry.handle_count,
        )

    def _handle_fields(self, pid: int) -> _HandleFields:
        if not self._may_open(pid):
            # psutil would learn the same slowly, per field; the path needs no handle.
            return _HandleFields(
                exe_path=self._path_without_handle(pid), command_line=_DENIED, username=_DENIED
            )
        try:
            process = self._process(pid)
        except psutil.NoSuchProcess:
            return _HandleFields(exe_path=_GONE, command_line=_GONE, username=_GONE)
        with process.oneshot():
            return _HandleFields(
                exe_path=_map(_read(process.exe), _non_empty),
                command_line=_map(_read(process.cmdline), _non_empty_tuple),
                username=_read(process.username),
            )

    def _path_without_handle(self, pid: int) -> Metric[str]:
        try:
            return _non_empty(self._image_path(pid))
        except ProcessGoneError:
            return _GONE
        except OSError:
            return Unavailable(UnavailableReason.ERROR)


def _non_empty(value: str) -> Metric[str]:
    # psutil reports "" (not an error) for kernel processes such as System; that is the
    # absence of an image path, not a path.
    return value if value else Unavailable(UnavailableReason.NOT_SUPPORTED)


def _non_empty_tuple(value: list[str]) -> Metric[tuple[str, ...]]:
    return tuple(value) if value else Unavailable(UnavailableReason.NOT_SUPPORTED)


def _read[T](read: Callable[[], T]) -> Metric[T]:
    try:
        return read()
    except psutil.AccessDenied:
        return Unavailable(UnavailableReason.ACCESS_DENIED)
    except psutil.NoSuchProcess:
        return _GONE
    except (psutil.Error, OSError):
        return Unavailable(UnavailableReason.ERROR)


def _map[T, R](metric: Metric[T], convert: Callable[[T], Metric[R]]) -> Metric[R]:
    if isinstance(metric, Unavailable):
        return metric
    return convert(metric)
