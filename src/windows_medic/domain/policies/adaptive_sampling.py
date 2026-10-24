"""Adaptive process-sampling state machine.

``NORMAL`` samples processes slowly. A suspect pressure signal switches to ``ESCALATED``
(fast sampling) for at most ``escalation_max``; escalation then yields to ``COOLDOWN``,
during which pressure is ignored, before returning to ``NORMAL``. The cool-down is what
prevents flapping pressure from producing an escalation storm.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


class SamplingMode(StrEnum):
    NORMAL = "normal"
    ESCALATED = "escalated"
    COOLDOWN = "cooldown"


@dataclass(frozen=True, slots=True)
class AdaptivePolicy:
    escalation_max: timedelta
    cooldown: timedelta

    def __post_init__(self) -> None:
        if self.escalation_max <= timedelta(0):
            raise ValueError("escalation_max must be positive")
        if self.cooldown < timedelta(0):
            raise ValueError("cooldown cannot be negative")


@dataclass(frozen=True, slots=True)
class SamplingState:
    mode: SamplingMode
    since: datetime

    @classmethod
    def initial(cls, now: datetime) -> "SamplingState":
        return cls(SamplingMode.NORMAL, now)


def advance(
    state: SamplingState, now: datetime, suspect: bool, policy: AdaptivePolicy
) -> SamplingState:
    """Return the state after observing *suspect* at *now*. Unchanged states are returned as-is."""
    elapsed = now - state.since
    if state.mode is SamplingMode.NORMAL:
        return SamplingState(SamplingMode.ESCALATED, now) if suspect else state
    if state.mode is SamplingMode.ESCALATED:
        if not suspect or elapsed >= policy.escalation_max:
            return SamplingState(SamplingMode.COOLDOWN, now)
        return state
    if elapsed >= policy.cooldown:
        return SamplingState(SamplingMode.NORMAL, now)
    return state
