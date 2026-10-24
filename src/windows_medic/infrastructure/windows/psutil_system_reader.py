"""psutil-backed :class:`SystemReader`."""

from collections.abc import Callable, Sequence
from typing import Protocol

import psutil

from windows_medic.application.ports.clock import Clock
from windows_medic.domain.errors import ObservationError
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason
from windows_medic.domain.models.samples import (
    CommitObservation,
    CpuTimes,
    DiskIoCounters,
    MemoryObservation,
    SystemObservation,
)
from windows_medic.infrastructure.windows.win32_performance import read_commit


class SystemReadError(ObservationError):
    """A system-wide metric that has no honest fallback could not be read."""


class _VirtualMemory(Protocol):
    @property
    def total(self) -> int: ...
    @property
    def available(self) -> int: ...


class _DiskCounters(Protocol):
    @property
    def read_bytes(self) -> int: ...
    @property
    def write_bytes(self) -> int: ...


class _SystemSource(Protocol):
    """The subset of the ``psutil`` module this adapter relies on."""

    def cpu_times(self) -> Sequence[float]: ...
    def cpu_count(self) -> int | None: ...
    def virtual_memory(self) -> _VirtualMemory: ...
    def pids(self) -> list[int]: ...
    def disk_io_counters(self) -> _DiskCounters | None: ...


class PsutilSystemReader:
    """Reads system-wide metrics through psutil plus one narrow Win32 call for commit."""

    def __init__(
        self,
        clock: Clock,
        *,
        source: _SystemSource = psutil,
        commit: Callable[[], Metric[CommitObservation]] = read_commit,
    ) -> None:
        self._clock = clock
        self._source = source
        self._commit = commit

    def snapshot(self) -> SystemObservation:
        observed_at = self._clock.now()
        cpu_count = self._source.cpu_count()
        if cpu_count is None:
            raise SystemReadError("psutil could not determine the logical CPU count")
        memory = self._source.virtual_memory()
        disk = self._source.disk_io_counters()
        return SystemObservation(
            observed_at=observed_at,
            cpu_times=_cpu_times(self._source.cpu_times()),
            cpu_count=cpu_count,
            memory=MemoryObservation(total_bytes=memory.total, available_bytes=memory.available),
            commit=self._commit(),
            process_count=len(self._source.pids()),
            disk_io=(
                Unavailable(UnavailableReason.NOT_SUPPORTED)
                if disk is None
                else DiskIoCounters(read_bytes=disk.read_bytes, write_bytes=disk.write_bytes)
            ),
        )


def _cpu_times(times: Sequence[float]) -> CpuTimes:
    # Mirrors psutil.cpu_percent: everything that is not idle counts as busy. On Windows the
    # tuple is (user, system, idle, interrupt, dpc); idle is always the third field.
    total = float(sum(times))
    idle = float(times[2])
    return CpuTimes(busy_seconds=total - idle, total_seconds=total)
