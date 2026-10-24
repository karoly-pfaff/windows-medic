"""Current system health: a bounded snapshot with ranked contributors.

Rates need two observations, so the use case samples twice across a short configured
window. Per-process CPU is derived only for identities present in both samples; a PID
reused inside the window gets no baseline rather than a number belonging to a dead process.
"""

from dataclasses import dataclass
from datetime import datetime

from windows_medic.application.ports.clock import Clock
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.application.ports.system_reader import SystemReader
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason, available
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.samples import (
    CommitObservation,
    MemoryObservation,
    ProcessSnapshot,
    SystemObservation,
)
from windows_medic.domain.policies.contributors import rank_top
from windows_medic.domain.policies.rates import (
    bytes_per_second,
    process_cpu_percent,
    system_cpu_percent,
)


@dataclass(frozen=True, slots=True)
class HealthLimits:
    """Bounds for one health measurement."""

    measurement_window_seconds: float
    top_contributors: int

    def __post_init__(self) -> None:
        if self.measurement_window_seconds <= 0:
            raise ValueError("measurement_window_seconds must be positive")
        if self.top_contributors < 0:
            raise ValueError("top_contributors cannot be negative")


@dataclass(frozen=True, slots=True)
class ProcessContribution:
    """One process's share of resources over the measurement window."""

    identity: ProcessIdentity
    name: Metric[str]
    cpu_percent: Metric[float]
    working_set_bytes: Metric[int]
    private_bytes: Metric[int]


@dataclass(frozen=True, slots=True)
class SystemHealth:
    """Typed result of :class:`GetSystemHealth`. Bounded by construction."""

    observed_at: datetime
    measurement_window_seconds: float
    cpu_percent: Metric[float]
    cpu_count: int
    memory: MemoryObservation
    commit: Metric[CommitObservation]
    process_count: int
    disk_read_bytes_per_second: Metric[float]
    disk_write_bytes_per_second: Metric[float]
    top_cpu: tuple[ProcessContribution, ...]
    top_memory: tuple[ProcessContribution, ...]
    skipped_process_count: int
    exited_process_count: int
    started_process_count: int


class GetSystemHealth:
    """Measure current system health over a short window."""

    def __init__(
        self,
        *,
        system_reader: SystemReader,
        process_reader: ProcessReader,
        clock: Clock,
        limits: HealthLimits,
    ) -> None:
        self._system_reader = system_reader
        self._process_reader = process_reader
        self._clock = clock
        self._limits = limits

    @property
    def limits(self) -> HealthLimits:
        return self._limits

    def execute(self) -> SystemHealth:
        measurement = measure(
            self._system_reader, self._process_reader, self._clock, limits=self._limits
        )
        return assess_health(measurement, limits=self._limits)


@dataclass(frozen=True, slots=True)
class Measurement:
    """Two system and process samples taken across the measurement window."""

    system_before: SystemObservation
    processes_before: ProcessSnapshot
    system_after: SystemObservation
    processes_after: ProcessSnapshot


def measure(
    system_reader: SystemReader,
    process_reader: ProcessReader,
    clock: Clock,
    *,
    limits: HealthLimits,
) -> Measurement:
    """Sample twice across the configured window. The only I/O in this module."""
    system_before = system_reader.snapshot()
    processes_before = process_reader.snapshot()
    clock.sleep(limits.measurement_window_seconds)
    return Measurement(
        system_before=system_before,
        processes_before=processes_before,
        system_after=system_reader.snapshot(),
        processes_after=process_reader.snapshot(),
    )


def assess_health(measurement: Measurement, *, limits: HealthLimits) -> SystemHealth:
    """Derive rates and ranked contributors from a measurement. Pure."""
    system_before, system_after = measurement.system_before, measurement.system_after
    processes_before, processes_after = measurement.processes_before, measurement.processes_after

    baseline = {observation.identity: observation for observation in processes_before.processes}
    contributions = tuple(
        _contribution(baseline.get(after.identity), after, cpu_count=system_after.cpu_count)
        for after in processes_after.processes
    )
    final_identities = {observation.identity for observation in processes_after.processes}

    return SystemHealth(
        observed_at=system_after.observed_at,
        measurement_window_seconds=limits.measurement_window_seconds,
        cpu_percent=system_cpu_percent(system_before.cpu_times, system_after.cpu_times),
        cpu_count=system_after.cpu_count,
        memory=system_after.memory,
        commit=system_after.commit,
        process_count=system_after.process_count,
        disk_read_bytes_per_second=_disk_rate(system_before, system_after, "read"),
        disk_write_bytes_per_second=_disk_rate(system_before, system_after, "write"),
        top_cpu=rank_top(
            contributions,
            metric=lambda c: c.cpu_percent,
            identity=lambda c: c.identity,
            limit=limits.top_contributors,
        ),
        top_memory=rank_top(
            contributions,
            metric=lambda c: c.working_set_bytes,
            identity=lambda c: c.identity,
            limit=limits.top_contributors,
        ),
        skipped_process_count=processes_after.skipped_count,
        exited_process_count=len(baseline.keys() - final_identities),
        started_process_count=len(final_identities - baseline.keys()),
    )


def _contribution(
    before: ProcessObservation | None, after: ProcessObservation, *, cpu_count: int
) -> ProcessContribution:
    cpu_percent: Metric[float] = (
        Unavailable(UnavailableReason.NO_BASELINE)
        if before is None
        else process_cpu_percent(before, after, cpu_count=cpu_count)
    )
    return ProcessContribution(
        identity=after.identity,
        name=after.name,
        cpu_percent=cpu_percent,
        working_set_bytes=after.working_set_bytes,
        private_bytes=after.private_bytes,
    )


def _disk_rate(
    before: SystemObservation, after: SystemObservation, direction: str
) -> Metric[float]:
    if not available(after.disk_io):
        return after.disk_io
    if not available(before.disk_io):
        return before.disk_io
    if direction == "read":
        before_bytes, after_bytes = before.disk_io.read_bytes, after.disk_io.read_bytes
    else:
        before_bytes, after_bytes = before.disk_io.write_bytes, after.disk_io.write_bytes
    return bytes_per_second(before_bytes, after_bytes, before.observed_at, after.observed_at)
