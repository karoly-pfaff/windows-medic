"""Process identity and per-process observations.

A Windows process is identified by ``(pid, create_time)``. PIDs are reused; a PID alone
never identifies a process (docs/architecture.md §3.1).
"""

from dataclasses import dataclass
from datetime import datetime

from windows_medic.domain.models.metric import Metric

# Windows process ids are DWORDs.
MAX_PID = 2**32 - 1


@dataclass(frozen=True, slots=True, order=True)
class ProcessIdentity:
    """Exact identity of one process instance. Ordered by ``(pid, create_time)``."""

    pid: int
    create_time: datetime

    def __post_init__(self) -> None:
        if not 0 <= self.pid <= MAX_PID:
            raise ValueError(f"pid must be between 0 and {MAX_PID}, got {self.pid}")
        if self.create_time.tzinfo is None:
            raise ValueError("create_time must be timezone-aware")

    def __str__(self) -> str:
        return f"pid {self.pid} @ {self.create_time.isoformat()}"


@dataclass(frozen=True, slots=True)
class ProcessObservation:
    """Facts read about one process at ``observed_at``.

    Counters (``cpu_time_seconds``, I/O bytes) are cumulative since process start; rates are
    derived by comparing two observations of the *same identity*.
    """

    identity: ProcessIdentity
    observed_at: datetime
    name: Metric[str]
    exe_path: Metric[str]
    command_line: Metric[tuple[str, ...]]
    parent_pid: Metric[int]
    username: Metric[str]
    session_id: Metric[int]
    cpu_time_seconds: Metric[float]
    working_set_bytes: Metric[int]
    private_bytes: Metric[int]
    io_read_bytes: Metric[int]
    io_write_bytes: Metric[int]
    thread_count: Metric[int]
    handle_count: Metric[int]
