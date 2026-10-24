"""PsutilSystemReader maps psutil module calls into a SystemObservation."""

import ctypes
from collections import namedtuple
from datetime import UTC, datetime

import pytest

from tests.fakes import FakeClock
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason
from windows_medic.domain.models.samples import CommitObservation, DiskIoCounters
from windows_medic.infrastructure.windows.psutil_system_reader import (
    PsutilSystemReader,
    SystemReadError,
)
from windows_medic.infrastructure.windows.win32_performance import (
    PerformanceInformation,
    query_performance_information,
    read_commit,
)

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)
GIB = 1024**3

WindowsCpuTimes = namedtuple("WindowsCpuTimes", ["user", "system", "idle", "interrupt", "dpc"])
VirtualMemory = namedtuple("VirtualMemory", ["total", "available"])
DiskCounters = namedtuple("DiskCounters", ["read_bytes", "write_bytes"])
DEFAULT_DISK = DiskCounters(read_bytes=100, write_bytes=200)


class FakeSource:
    def __init__(
        self,
        *,
        cpu_count: int | None = 8,
        disk: DiskCounters | None = DEFAULT_DISK,
    ) -> None:
        self._cpu_count = cpu_count
        self._disk = disk

    def cpu_times(self) -> WindowsCpuTimes:
        return WindowsCpuTimes(user=100.0, system=50.0, idle=800.0, interrupt=5.0, dpc=1.0)

    def cpu_count(self) -> int | None:
        return self._cpu_count

    def virtual_memory(self) -> VirtualMemory:
        return VirtualMemory(total=32 * GIB, available=12 * GIB)

    def pids(self) -> list[int]:
        return [0, 4, 100, 200]

    def disk_io_counters(self) -> DiskCounters | None:
        return self._disk


COMMIT = CommitObservation(limit_bytes=40 * GIB, used_bytes=21 * GIB)


def reader(source: FakeSource | None = None) -> PsutilSystemReader:
    return PsutilSystemReader(
        clock=FakeClock(T0), source=source or FakeSource(), commit=lambda: COMMIT
    )


def test_busy_time_is_everything_except_idle_matching_psutil() -> None:
    observation = reader().snapshot()

    assert observation.cpu_times.total_seconds == 956.0
    assert observation.cpu_times.busy_seconds == 156.0


def test_maps_memory_cpu_count_process_count_and_timestamp() -> None:
    observation = reader().snapshot()

    assert observation.observed_at == T0
    assert observation.cpu_count == 8
    assert observation.memory.total_bytes == 32 * GIB
    assert observation.memory.available_bytes == 12 * GIB
    assert observation.process_count == 4
    assert observation.disk_io == DiskIoCounters(read_bytes=100, write_bytes=200)
    assert observation.commit == COMMIT


def test_missing_disk_counters_are_not_supported() -> None:
    observation = reader(FakeSource(disk=None)).snapshot()

    assert observation.disk_io == Unavailable(UnavailableReason.NOT_SUPPORTED)


def test_unknown_cpu_count_is_an_error_not_a_fake_default() -> None:
    with pytest.raises(SystemReadError, match="CPU count"):
        reader(FakeSource(cpu_count=None)).snapshot()


class TestReadCommit:
    def test_converts_pages_to_bytes(self) -> None:
        commit = read_commit(query=lambda: (1000, 4000, 4096))

        assert commit == CommitObservation(limit_bytes=4000 * 4096, used_bytes=1000 * 4096)

    def test_unsupported_platform(self) -> None:
        def unsupported() -> tuple[int, int, int]:
            raise NotImplementedError

        assert read_commit(query=unsupported) == Unavailable(UnavailableReason.NOT_SUPPORTED)

    def test_os_failure_is_an_error(self) -> None:
        def failing() -> tuple[int, int, int]:
            raise OSError("GetPerformanceInfo failed")

        assert read_commit(query=failing) == Unavailable(UnavailableReason.ERROR)

    def test_nonsensical_values_are_inconsistent(self) -> None:
        result: Metric[CommitObservation] = read_commit(query=lambda: (5000, 4000, 4096))

        assert result == Unavailable(UnavailableReason.INCONSISTENT)


class FakePsapi:
    def __init__(self, succeed: bool) -> None:
        self._succeed = succeed

    def GetPerformanceInfo(  # noqa: N802 - Win32 export name
        self, info: "ctypes._Pointer[PerformanceInformation]", size: int
    ) -> int:
        if not self._succeed:
            return 0
        structure = info.contents
        assert size == ctypes.sizeof(structure)
        structure.CommitTotal, structure.CommitLimit, structure.PageSize = 10, 20, 4096
        return 1


class TestQueryPerformanceInformation:
    def test_reads_commit_pages_from_the_structure(self) -> None:
        assert query_performance_information(psapi=FakePsapi(succeed=True)) == (10, 20, 4096)

    def test_failure_raises_os_error(self) -> None:
        with pytest.raises(OSError, match=r"\[WinError"):
            query_performance_information(psapi=FakePsapi(succeed=False))
