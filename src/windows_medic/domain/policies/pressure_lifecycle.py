"""Sustained-pressure lifecycle for one pressure kind.

``NONE -> SUSPECT`` when the threshold is crossed; ``SUSPECT -> OPEN`` once it has held for
``duration``; ``OPEN -> RECOVERING`` when it clears; ``RECOVERING -> NONE`` (closed) once it
has stayed clear for ``recovery``; pressure returning during recovery *reopens the same
incident*. A streak that clears before ``duration`` never becomes an incident.

Pure and immutable: ``advance`` returns the next tracker plus the transition that happened.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


class Phase(StrEnum):
    NONE = "none"
    SUSPECT = "suspect"
    OPEN = "open"
    RECOVERING = "recovering"


class Transition(StrEnum):
    NONE = "none"
    SUSPECT_STARTED = "suspect_started"
    SUSPECT_CLEARED = "suspect_cleared"
    OPENED = "opened"
    RECOVERING = "recovering"
    REOPENED = "reopened"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class LifecyclePolicy:
    duration: timedelta
    recovery: timedelta

    def __post_init__(self) -> None:
        if self.duration <= timedelta(0):
            raise ValueError("duration must be positive")
        if self.recovery < timedelta(0):
            raise ValueError("recovery cannot be negative")


@dataclass(frozen=True, slots=True)
class PressureTracker:
    """State of one pressure kind. ``since`` is when the current streak/incident began."""

    phase: Phase
    since: datetime | None
    recovering_since: datetime | None
    last_observed: datetime | None

    @classmethod
    def idle(cls) -> "PressureTracker":
        return cls(Phase.NONE, None, None, None)

    def advance(
        self, now: datetime, *, above: bool, policy: LifecyclePolicy
    ) -> tuple["PressureTracker", Transition]:
        current = self
        if self.last_observed is not None and now < self.last_observed:
            # The wall clock stepped back (NTP, VM resume). Treat the step as instantaneous:
            # shift this tracker onto the new timeline so elapsed durations are kept.
            current = self._shifted(now - self.last_observed)
        tracker, transition = current._step(now, above, policy)
        return (
            PressureTracker(tracker.phase, tracker.since, tracker.recovering_since, now),
            transition,
        )

    def _shifted(self, delta: timedelta) -> "PressureTracker":
        return PressureTracker(
            self.phase,
            None if self.since is None else self.since + delta,
            None if self.recovering_since is None else self.recovering_since + delta,
            None if self.last_observed is None else self.last_observed + delta,
        )

    def _step(
        self, now: datetime, above: bool, policy: LifecyclePolicy
    ) -> tuple["PressureTracker", Transition]:
        if self.phase is Phase.NONE:
            if above:
                return PressureTracker(Phase.SUSPECT, now, None, now), Transition.SUSPECT_STARTED
            return self, Transition.NONE
        if self.phase is Phase.SUSPECT:
            return self._step_suspect(now, above, policy)
        if self.phase is Phase.OPEN:
            if above:
                return self, Transition.NONE
            return PressureTracker(Phase.RECOVERING, self.since, now, now), Transition.RECOVERING
        return self._step_recovering(now, above, policy)

    def _step_suspect(
        self, now: datetime, above: bool, policy: LifecyclePolicy
    ) -> tuple["PressureTracker", Transition]:
        if not above:
            return PressureTracker.idle(), Transition.SUSPECT_CLEARED
        if self.since is not None and now - self.since >= policy.duration:
            return PressureTracker(Phase.OPEN, self.since, None, now), Transition.OPENED
        return self, Transition.NONE

    def _step_recovering(
        self, now: datetime, above: bool, policy: LifecyclePolicy
    ) -> tuple["PressureTracker", Transition]:
        if above:
            return PressureTracker(Phase.OPEN, self.since, None, now), Transition.REOPENED
        if self.recovering_since is not None and now - self.recovering_since >= policy.recovery:
            return PressureTracker.idle(), Transition.CLOSED
        return self, Transition.NONE
