"""System-level observations and process snapshots."""

from dataclasses import dataclass
from datetime import datetime

from windows_medic.domain.models.metric import Metric
from windows_medic.domain.models.process import ProcessObservation


@dataclass(frozen=True, slots=True)
class CpuTimes:
    """Cumulative CPU time across all logical processors since boot."""

    busy_seconds: float
    total_seconds: float

    def __post_init__(self) -> None:
        if self.busy_seconds < 0 or self.total_seconds < 0:
            raise ValueError("CPU times cannot be negative")
        if self.busy_seconds > self.total_seconds:
            raise ValueError("busy_seconds cannot exceed total_seconds")


@dataclass(frozen=True, slots=True)
class MemoryObservation:
    """Physical memory."""

    total_bytes: int
    available_bytes: int

    def __post_init__(self) -> None:
        if self.total_bytes <= 0:
            raise ValueError("total_bytes must be positive")
        if not 0 <= self.available_bytes <= self.total_bytes:
            raise ValueError("available_bytes must be between 0 and total_bytes")

    @property
    def used_bytes(self) -> int:
        return self.total_bytes - self.available_bytes

    @property
    def percent_used(self) -> float:
        return self.used_bytes / self.total_bytes * 100.0


@dataclass(frozen=True, slots=True)
class CommitObservation:
    """System commit charge against the commit limit (pagefile-backed)."""

    limit_bytes: int
    used_bytes: int

    def __post_init__(self) -> None:
        if self.limit_bytes <= 0:
            raise ValueError("limit_bytes must be positive")
        if not 0 <= self.used_bytes <= self.limit_bytes:
            raise ValueError("used_bytes must be between 0 and limit_bytes")

    @property
    def percent_used(self) -> float:
        return self.used_bytes / self.limit_bytes * 100.0


@dataclass(frozen=True, slots=True)
class DiskIoCounters:
    """Cumulative bytes transferred across all physical disks since boot."""

    read_bytes: int
    write_bytes: int

    def __post_init__(self) -> None:
        if self.read_bytes < 0 or self.write_bytes < 0:
            raise ValueError("I/O counters cannot be negative")


@dataclass(frozen=True, slots=True)
class SystemObservation:
    """System-wide facts read at ``observed_at``. Counters are cumulative."""

    observed_at: datetime
    cpu_times: CpuTimes
    cpu_count: int
    memory: MemoryObservation
    commit: Metric[CommitObservation]
    process_count: int
    disk_io: Metric[DiskIoCounters]

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.cpu_count <= 0:
            raise ValueError("cpu_count must be positive")
        if self.process_count < 0:
            raise ValueError("process_count cannot be negative")


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    """Every process that could be identified during one collection pass.

    ``skipped_count`` records processes that exited or could not be identified while the
    pass ran; they are evidence of churn, not an error.
    """

    observed_at: datetime
    processes: tuple[ProcessObservation, ...]
    skipped_count: int

    def __post_init__(self) -> None:
        if self.skipped_count < 0:
            raise ValueError("skipped_count cannot be negative")
