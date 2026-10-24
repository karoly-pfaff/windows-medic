"""In-memory rolling evidence kept by the agent.

Two ring buffers, both bounded by the rolling window *and* an item cap, so escalated
sampling cannot grow memory without bound. The incident engine reads pre-trigger evidence
from here.
"""

from dataclasses import dataclass
from datetime import timedelta

from windows_medic.domain.models.history import Retention, RingBuffer
from windows_medic.domain.models.samples import ProcessSnapshot, SystemObservation


@dataclass(frozen=True, slots=True)
class EvidenceRetention:
    window: timedelta
    max_system_samples: int
    max_process_snapshots: int


class RollingEvidence:
    """Bounded system and process history."""

    def __init__(self, retention: EvidenceRetention) -> None:
        self.system: RingBuffer[SystemObservation] = RingBuffer(
            Retention(retention.window, retention.max_system_samples),
            timestamp=lambda observation: observation.observed_at,
        )
        self.processes: RingBuffer[ProcessSnapshot] = RingBuffer(
            Retention(retention.window, retention.max_process_snapshots),
            timestamp=lambda snapshot: snapshot.observed_at,
        )

    def record_system(self, observation: SystemObservation) -> None:
        self.system.append(observation)

    def record_processes(self, snapshot: ProcessSnapshot) -> None:
        self.processes.append(snapshot)
