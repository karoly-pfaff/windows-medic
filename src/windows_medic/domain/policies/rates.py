"""Rates derived from two cumulative observations.

Pure functions: no clocks, no OS access. A rate needs a baseline of the *same identity*;
counters that fail to advance or go backwards are reported as inconsistent rather than
silently producing a misleading number.
"""

from datetime import datetime

from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason, available
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.samples import CpuTimes

_INCONSISTENT = Unavailable(UnavailableReason.INCONSISTENT)


def system_cpu_percent(before: CpuTimes, after: CpuTimes) -> Metric[float]:
    """Share of elapsed CPU time that was busy, 0-100."""
    total_delta = after.total_seconds - before.total_seconds
    busy_delta = after.busy_seconds - before.busy_seconds
    if total_delta <= 0 or busy_delta < 0:
        return _INCONSISTENT
    return _clamp_percent(busy_delta / total_delta * 100.0)


def process_cpu_percent(
    before: ProcessObservation, after: ProcessObservation, *, cpu_count: int
) -> Metric[float]:
    """CPU time consumed between two observations as a share of the whole machine, 0-100.

    Raises:
        ValueError: If the observations belong to different identities (a PID-reuse bug in
            the caller) or ``cpu_count`` is not positive.
    """
    if before.identity != after.identity:
        raise ValueError(
            f"observations have different identity: {before.identity} vs {after.identity}"
        )
    if cpu_count <= 0:
        raise ValueError(f"cpu_count must be positive, got {cpu_count}")
    if not available(after.cpu_time_seconds):
        return after.cpu_time_seconds
    if not available(before.cpu_time_seconds):
        return before.cpu_time_seconds

    elapsed = (after.observed_at - before.observed_at).total_seconds()
    cpu_delta = after.cpu_time_seconds - before.cpu_time_seconds
    if elapsed <= 0 or cpu_delta < 0:
        return _INCONSISTENT
    return _clamp_percent(cpu_delta / (elapsed * cpu_count) * 100.0)


def bytes_per_second(
    before: Metric[int], after: Metric[int], before_at: datetime, after_at: datetime
) -> Metric[float]:
    """Transfer rate between two cumulative byte counters."""
    if not available(after):
        return after
    if not available(before):
        return before
    elapsed = (after_at - before_at).total_seconds()
    delta = after - before
    if elapsed <= 0 or delta < 0:
        return _INCONSISTENT
    return delta / elapsed


def _clamp_percent(value: float) -> float:
    return min(max(value, 0.0), 100.0)
