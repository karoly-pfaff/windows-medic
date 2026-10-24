"""Rank resource contributors over the whole lookback window, not only the latest sample.

Each incident carries the top contributors captured when it opened; the on-demand
measurement adds what is running now. Both are merged per exact identity and ranked by
the largest *share of the machine* seen anywhere in the window (CPU share or working-set
share of physical memory), so a process that drove an incident ten minutes ago and has
since exited still outranks whatever happens to be busy at this instant. Ordering is
total and deterministic.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from windows_medic.domain.models.incident import Incident, IncidentKind, ProcessEvidenceSample
from windows_medic.domain.models.metric import Metric, available
from windows_medic.domain.models.process import ProcessIdentity


@dataclass(frozen=True, slots=True)
class IncidentContribution:
    """What one process contributed within one incident's evidence window."""

    incident_id: str
    kind: IncidentKind
    window: tuple[datetime, datetime]
    cpu_percent: Metric[float]
    working_set_bytes: Metric[int]


@dataclass(frozen=True, slots=True)
class ContributorEvidence:
    identity: ProcessIdentity
    name: Metric[str]
    exe_path: Metric[str]
    incident_contributions: tuple[IncidentContribution, ...]
    current: ProcessEvidenceSample | None
    cpu_share: float
    memory_share: float

    @property
    def dominant_share(self) -> float:
        return max(self.cpu_share, self.memory_share)

    @property
    def present_now(self) -> bool:
        return self.current is not None


def rank_contributors(
    incidents: Sequence[Incident],
    current: Sequence[ProcessEvidenceSample],
    *,
    memory_total_bytes: int,
    limit: int,
    max_incidents_per_contributor: int,
) -> tuple[ContributorEvidence, ...]:
    """Merge incident and current contributions per identity; top *limit* by dominant share.

    Processes with no measurable share (every metric unavailable) are left out: an unknown
    value is not a small value.
    """
    if memory_total_bytes <= 0:
        raise ValueError("memory_total_bytes must be positive")
    newest_first = sorted(incidents, key=lambda i: (i.started_at, i.id), reverse=True)

    history: dict[ProcessIdentity, list[IncidentContribution]] = {}
    latest_sample: dict[ProcessIdentity, ProcessEvidenceSample] = {}
    for inc in newest_first:
        for sample in inc.contributors:
            history.setdefault(sample.identity, []).append(
                IncidentContribution(
                    incident_id=inc.id,
                    kind=inc.kind,
                    window=inc.evidence_window,
                    cpu_percent=sample.cpu_percent,
                    working_set_bytes=sample.working_set_bytes,
                )
            )
            latest_sample.setdefault(sample.identity, sample)
    now_by_identity = {sample.identity: sample for sample in current}

    merged: list[ContributorEvidence] = []
    for identity in history.keys() | now_by_identity.keys():
        contributions = tuple(history.get(identity, ())[:max_incidents_per_contributor])
        now = now_by_identity.get(identity)
        describer = now if now is not None else latest_sample[identity]
        cpu_values = [c.cpu_percent for c in contributions if available(c.cpu_percent)]
        memory_values = [
            c.working_set_bytes for c in contributions if available(c.working_set_bytes)
        ]
        if now is not None:
            if available(now.cpu_percent):
                cpu_values.append(now.cpu_percent)
            if available(now.working_set_bytes):
                memory_values.append(now.working_set_bytes)
        if not cpu_values and not memory_values:
            continue
        merged.append(
            ContributorEvidence(
                identity=identity,
                name=describer.name,
                exe_path=describer.exe_path,
                incident_contributions=contributions,
                current=now,
                cpu_share=max(cpu_values, default=0.0),
                memory_share=max(memory_values, default=0) / memory_total_bytes * 100.0,
            )
        )

    merged.sort(
        key=lambda c: (-c.dominant_share, -len(c.incident_contributions), c.identity),
    )
    return tuple(merged[:limit])
