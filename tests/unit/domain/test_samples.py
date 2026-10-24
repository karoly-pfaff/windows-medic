"""System observation value objects validate their invariants."""

from datetime import UTC, datetime

import pytest

from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.samples import (
    CommitObservation,
    CpuTimes,
    DiskIoCounters,
    MemoryObservation,
    ProcessSnapshot,
    SystemObservation,
)

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)


class TestCpuTimes:
    def test_busy_may_not_exceed_total(self) -> None:
        with pytest.raises(ValueError, match="busy"):
            CpuTimes(busy_seconds=11.0, total_seconds=10.0)

    def test_negative_values_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="negative"):
            CpuTimes(busy_seconds=-1.0, total_seconds=10.0)


class TestMemoryObservation:
    def test_percent_used_is_derived_from_bytes(self) -> None:
        memory = MemoryObservation(total_bytes=1000, available_bytes=250)

        assert memory.used_bytes == 750
        assert memory.percent_used == 75.0

    def test_available_may_not_exceed_total(self) -> None:
        with pytest.raises(ValueError, match="available"):
            MemoryObservation(total_bytes=100, available_bytes=101)

    def test_total_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="total"):
            MemoryObservation(total_bytes=0, available_bytes=0)


class TestCommitObservation:
    def test_percent_used_is_derived_from_bytes(self) -> None:
        commit = CommitObservation(limit_bytes=200, used_bytes=50)

        assert commit.percent_used == 25.0

    def test_limit_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="limit"):
            CommitObservation(limit_bytes=0, used_bytes=0)

    def test_used_may_not_exceed_limit(self) -> None:
        with pytest.raises(ValueError, match="used"):
            CommitObservation(limit_bytes=10, used_bytes=11)


class TestDiskIoCounters:
    def test_negative_counters_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="negative"):
            DiskIoCounters(read_bytes=-1, write_bytes=0)


class TestSystemObservation:
    def test_requires_timezone_aware_timestamp_and_positive_cpu_count(self) -> None:
        memory = MemoryObservation(total_bytes=100, available_bytes=50)
        cpu = CpuTimes(busy_seconds=1.0, total_seconds=2.0)
        commit = Unavailable(UnavailableReason.NOT_SUPPORTED)

        with pytest.raises(ValueError, match="cpu_count"):
            SystemObservation(
                observed_at=T0,
                cpu_times=cpu,
                cpu_count=0,
                memory=memory,
                commit=commit,
                process_count=1,
                disk_io=commit,
            )
        with pytest.raises(ValueError, match="timezone-aware"):
            SystemObservation(
                observed_at=datetime(2026, 1, 1),  # noqa: DTZ001
                cpu_times=cpu,
                cpu_count=1,
                memory=memory,
                commit=commit,
                process_count=1,
                disk_io=commit,
            )

    def test_process_count_may_not_be_negative(self) -> None:
        with pytest.raises(ValueError, match="process_count"):
            SystemObservation(
                observed_at=T0,
                cpu_times=CpuTimes(busy_seconds=1.0, total_seconds=2.0),
                cpu_count=1,
                memory=MemoryObservation(total_bytes=100, available_bytes=50),
                commit=Unavailable(UnavailableReason.NOT_SUPPORTED),
                process_count=-1,
                disk_io=Unavailable(UnavailableReason.NOT_SUPPORTED),
            )


class TestProcessSnapshot:
    def test_skipped_count_may_not_be_negative(self) -> None:
        with pytest.raises(ValueError, match="skipped"):
            ProcessSnapshot(observed_at=T0, processes=(), skipped_count=-1)
