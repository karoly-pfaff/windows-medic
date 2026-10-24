"""Reduce raw observations into compact, bounded incident evidence."""

from windows_medic.domain.models.incident import ProcessEvidenceSample, SystemEvidenceSample
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason, available
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.samples import ProcessSnapshot, SystemObservation
from windows_medic.domain.policies.contributors import rank_top
from windows_medic.domain.policies.rates import process_cpu_percent

_ELLIPSIS = "..."


def summarise_system(
    observation: SystemObservation, cpu_percent: Metric[float]
) -> SystemEvidenceSample:
    return SystemEvidenceSample(
        observed_at=observation.observed_at,
        cpu_percent=cpu_percent,
        memory_percent_used=observation.memory.percent_used,
        memory_available_bytes=observation.memory.available_bytes,
        process_count=observation.process_count,
    )


def top_contributors(
    before: ProcessSnapshot | None,
    after: ProcessSnapshot,
    *,
    cpu_count: int,
    limit: int,
    max_command_line: int,
) -> tuple[ProcessEvidenceSample, ...]:
    """Top processes by CPU over ``before -> after``; by working set when there is no baseline."""
    samples = contribution_samples(
        before, after, cpu_count=cpu_count, max_command_line=max_command_line
    )
    by_cpu = rank_top(
        samples, metric=lambda s: s.cpu_percent, identity=lambda s: s.identity, limit=limit
    )
    if by_cpu:
        return by_cpu
    return rank_top(
        samples, metric=lambda s: s.working_set_bytes, identity=lambda s: s.identity, limit=limit
    )


def contribution_samples(
    before: ProcessSnapshot | None,
    after: ProcessSnapshot,
    *,
    cpu_count: int,
    max_command_line: int,
) -> tuple[ProcessEvidenceSample, ...]:
    """One compact sample per process in *after*, with CPU derived against *before*."""
    baseline = {} if before is None else {o.identity: o for o in before.processes}
    return tuple(
        _sample(baseline.get(o.identity), o, cpu_count=cpu_count, max_command_line=max_command_line)
        for o in after.processes
    )


def _sample(
    before: ProcessObservation | None,
    after: ProcessObservation,
    *,
    cpu_count: int,
    max_command_line: int,
) -> ProcessEvidenceSample:
    cpu: Metric[float] = (
        Unavailable(UnavailableReason.NO_BASELINE)
        if before is None
        else process_cpu_percent(before, after, cpu_count=cpu_count)
    )
    command_line: Metric[str] = (
        _truncate(" ".join(after.command_line), max_command_line)
        if available(after.command_line)
        else after.command_line
    )
    return ProcessEvidenceSample(
        identity=after.identity,
        name=after.name,
        exe_path=after.exe_path,
        command_line=command_line,
        cpu_percent=cpu,
        working_set_bytes=after.working_set_bytes,
        private_bytes=after.private_bytes,
    )


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(limit - len(_ELLIPSIS), 0)] + _ELLIPSIS
