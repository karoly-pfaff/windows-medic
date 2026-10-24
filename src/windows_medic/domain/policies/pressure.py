"""Pressure signals.

This module provides the instantaneous signal that drives adaptive sampling. Sustained
pressure (duration thresholds, incident lifecycle) is layered on top in the incident engine.
"""

from dataclasses import dataclass

from windows_medic.domain.models.metric import Metric, available
from windows_medic.domain.models.samples import MemoryObservation

_FULL_PERCENT = 100.0


@dataclass(frozen=True, slots=True)
class PressureThresholds:
    cpu_percent: float
    memory_percent: float
    memory_available_floor_bytes: int

    def __post_init__(self) -> None:
        if not 0 < self.cpu_percent <= _FULL_PERCENT:
            raise ValueError("cpu_percent must be within (0, 100]")
        if not 0 < self.memory_percent <= _FULL_PERCENT:
            raise ValueError("memory_percent must be within (0, 100]")
        if self.memory_available_floor_bytes < 0:
            raise ValueError("memory_available_floor_bytes cannot be negative")


@dataclass(frozen=True, slots=True)
class PressureSignal:
    cpu: bool
    memory: bool

    @property
    def suspect(self) -> bool:
        return self.cpu or self.memory


def instant_pressure(
    cpu_percent: Metric[float], memory: MemoryObservation, thresholds: PressureThresholds
) -> PressureSignal:
    """Evaluate one sample against the thresholds. An unavailable CPU figure is not a signal."""
    cpu = available(cpu_percent) and cpu_percent >= thresholds.cpu_percent
    memory_high = (
        memory.percent_used >= thresholds.memory_percent
        or memory.available_bytes < thresholds.memory_available_floor_bytes
    )
    return PressureSignal(cpu=cpu, memory=memory_high)
