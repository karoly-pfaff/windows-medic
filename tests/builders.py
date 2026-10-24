"""Builders for domain observations with sensible defaults, so tests state only what matters."""

from datetime import UTC, datetime, timedelta

from windows_medic.domain.models.incident import (
    EvidenceLimits,
    Incident,
    IncidentKind,
    ProcessEvidenceSample,
    SystemEvidenceSample,
    begin_recovery,
    close_incident,
    open_incident,
)
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason
from windows_medic.domain.models.network import (
    AddressFamily,
    ListeningEndpoint,
    TransportProtocol,
)
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.samples import (
    CommitObservation,
    CpuTimes,
    DiskIoCounters,
    MemoryObservation,
    ProcessSnapshot,
    SystemObservation,
)

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)
BOOT = T0 - timedelta(hours=3)
GIB = 1024**3

NOT_SUPPORTED = Unavailable(UnavailableReason.NOT_SUPPORTED)
DEFAULT_COMMIT = CommitObservation(limit_bytes=48 * GIB, used_bytes=20 * GIB)
NO_DISK_IO = DiskIoCounters(read_bytes=0, write_bytes=0)


def identity(pid: int, created: datetime = BOOT) -> ProcessIdentity:
    return ProcessIdentity(pid, created)


def process(
    pid: int,
    *,
    created: datetime = BOOT,
    observed_at: datetime = T0,
    name: Metric[str] = "proc.exe",
    cpu_time_seconds: Metric[float] = 0.0,
    working_set_bytes: Metric[int] = 100 * 1024**2,
    private_bytes: Metric[int] = 80 * 1024**2,
    parent_pid: Metric[int] = 4,
) -> ProcessObservation:
    return ProcessObservation(
        identity=identity(pid, created),
        observed_at=observed_at,
        name=name,
        exe_path=f"C:\\bin\\{name}" if isinstance(name, str) else name,
        command_line=(name,) if isinstance(name, str) else name,
        parent_pid=parent_pid,
        username="DESKTOP\\user",
        session_id=1,
        cpu_time_seconds=cpu_time_seconds,
        working_set_bytes=working_set_bytes,
        private_bytes=private_bytes,
        io_read_bytes=0,
        io_write_bytes=0,
        thread_count=4,
        handle_count=120,
    )


def process_snapshot(
    *processes: ProcessObservation, observed_at: datetime = T0, skipped_count: int = 0
) -> ProcessSnapshot:
    return ProcessSnapshot(
        observed_at=observed_at, processes=tuple(processes), skipped_count=skipped_count
    )


def system(
    *,
    observed_at: datetime = T0,
    busy_seconds: float = 1000.0,
    total_seconds: float = 10_000.0,
    cpu_count: int = 8,
    total_bytes: int = 32 * GIB,
    available_bytes: int = 16 * GIB,
    commit: Metric[CommitObservation] = DEFAULT_COMMIT,
    process_count: int = 200,
    disk_io: Metric[DiskIoCounters] = NO_DISK_IO,
) -> SystemObservation:
    return SystemObservation(
        observed_at=observed_at,
        cpu_times=CpuTimes(busy_seconds=busy_seconds, total_seconds=total_seconds),
        cpu_count=cpu_count,
        memory=MemoryObservation(total_bytes=total_bytes, available_bytes=available_bytes),
        commit=commit,
        process_count=process_count,
        disk_io=disk_io,
    )


def listener(
    port: int, pid: int | None, *, family: AddressFamily = AddressFamily.IPV4
) -> ListeningEndpoint:
    return ListeningEndpoint(
        protocol=TransportProtocol.TCP,
        family=family,
        address="127.0.0.1" if family is AddressFamily.IPV4 else "::1",
        port=port,
        owner_pid=pid,
    )


EVIDENCE_LIMITS = EvidenceLimits(
    max_system_samples=100, max_contributors=10, high_severity_after=timedelta(seconds=120)
)


def system_sample(
    observed_at: datetime = T0,
    *,
    cpu_percent: Metric[float] = 95.0,
    memory_percent_used: float = 50.0,
    memory_available_bytes: int = 16 * GIB,
) -> SystemEvidenceSample:
    return SystemEvidenceSample(
        observed_at=observed_at,
        cpu_percent=cpu_percent,
        memory_percent_used=memory_percent_used,
        memory_available_bytes=memory_available_bytes,
        process_count=300,
    )


def contributor(
    pid: int,
    *,
    created: datetime = BOOT,
    name: Metric[str] = "proc.exe",
    cpu_percent: Metric[float] = 30.0,
    working_set_bytes: Metric[int] = 100 * 1024**2,
) -> ProcessEvidenceSample:
    return ProcessEvidenceSample(
        identity=identity(pid, created),
        name=name,
        exe_path=f"C:\\bin\\{name}" if isinstance(name, str) else name,
        command_line=name,
        cpu_percent=cpu_percent,
        working_set_bytes=working_set_bytes,
        private_bytes=working_set_bytes,
    )


def incident(
    incident_id: str = "inc-1",
    *,
    kind: IncidentKind = IncidentKind.CPU_PRESSURE,
    started_at: datetime = T0 - timedelta(minutes=10),
    duration: timedelta | None = timedelta(minutes=2),
    threshold: float = 90.0,
    peak: float = 95.0,
    contributors: tuple[ProcessEvidenceSample, ...] = (),
) -> Incident:
    """An incident that started at *started_at*; closed after *duration* unless ``None``."""
    triggered = started_at + timedelta(seconds=20)
    memory = peak if kind is IncidentKind.MEMORY_PRESSURE else 50.0
    cpu = peak if kind is IncidentKind.CPU_PRESSURE else 10.0
    opened = open_incident(
        incident_id=incident_id,
        kind=kind,
        started_at=started_at,
        triggered_at=triggered,
        threshold=threshold,
        pre_trigger=(system_sample(triggered, cpu_percent=cpu, memory_percent_used=memory),),
        contributors=contributors,
        evidence_window=(started_at - timedelta(seconds=60), triggered),
        limits=EVIDENCE_LIMITS,
    )
    if duration is None:
        return opened
    recovering = begin_recovery(opened, started_at + duration)
    return close_incident(
        recovering, started_at + duration + timedelta(seconds=30), EVIDENCE_LIMITS
    )
