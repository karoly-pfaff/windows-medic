"""Sustained-pressure lifecycle: suspect -> open -> recovering -> closed, without storms."""

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from windows_medic.domain.policies.pressure_lifecycle import (
    LifecyclePolicy,
    Phase,
    PressureTracker,
    Transition,
)

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)
POLICY = LifecyclePolicy(duration=timedelta(seconds=20), recovery=timedelta(seconds=30))


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def drive(*steps: tuple[float, bool]) -> tuple[PressureTracker, list[Transition]]:
    tracker = PressureTracker.idle()
    transitions: list[Transition] = []
    for seconds, above in steps:
        tracker, transition = tracker.advance(at(seconds), above=above, policy=POLICY)
        transitions.append(transition)
    return tracker, transitions


class TestOpening:
    def test_idle_tracker_has_no_incident(self) -> None:
        tracker = PressureTracker.idle()

        assert tracker.phase is Phase.NONE
        assert tracker.since is None

    def test_crossing_the_threshold_starts_a_suspect_streak(self) -> None:
        tracker, transitions = drive((0, True))

        assert tracker.phase is Phase.SUSPECT
        assert tracker.since == at(0)
        assert transitions == [Transition.SUSPECT_STARTED]

    def test_a_spike_shorter_than_the_duration_never_opens(self) -> None:
        tracker, transitions = drive((0, True), (10, True), (19, True), (21, False))

        assert tracker.phase is Phase.NONE
        assert Transition.OPENED not in transitions
        assert transitions[-1] is Transition.SUSPECT_CLEARED

    def test_sustained_pressure_opens_exactly_once(self) -> None:
        tracker, transitions = drive((0, True), (10, True), (20, True), (30, True), (200, True))

        assert tracker.phase is Phase.OPEN
        assert tracker.since == at(0)
        assert transitions.count(Transition.OPENED) == 1
        assert transitions[2] is Transition.OPENED
        assert transitions[3:] == [Transition.NONE, Transition.NONE]

    def test_opens_at_exactly_the_duration(self) -> None:
        _, transitions = drive((0, True), (19.999, True))
        assert Transition.OPENED not in transitions

        _, transitions = drive((0, True), (20, True))
        assert transitions[-1] is Transition.OPENED


class TestRecovery:
    def test_clearing_while_open_starts_recovery_not_closure(self) -> None:
        tracker, transitions = drive((0, True), (20, True), (22, False))

        assert tracker.phase is Phase.RECOVERING
        assert tracker.recovering_since == at(22)
        assert transitions[-1] is Transition.RECOVERING

    def test_closes_after_the_recovery_cool_down(self) -> None:
        tracker, transitions = drive((0, True), (20, True), (22, False), (40, False), (52, False))

        assert tracker.phase is Phase.NONE
        assert transitions[-2] is Transition.NONE
        assert transitions[-1] is Transition.CLOSED

    def test_pressure_returning_during_recovery_reopens_the_same_incident(self) -> None:
        tracker, transitions = drive((0, True), (20, True), (22, False), (30, True))

        assert tracker.phase is Phase.OPEN
        assert tracker.since == at(0)
        assert transitions[-1] is Transition.REOPENED
        assert transitions.count(Transition.OPENED) == 1

    def test_after_closing_new_pressure_is_a_new_streak(self) -> None:
        tracker, transitions = drive(
            (0, True), (20, True), (22, False), (60, False), (70, True), (90, True)
        )

        assert transitions.count(Transition.OPENED) == 2
        assert tracker.since == at(70)


class TestStormResistance:
    def test_flapping_around_the_threshold_while_open_never_opens_a_second_time(self) -> None:
        steps: list[tuple[float, bool]] = [(0, True), (20, True)]
        steps.extend((22 + i * 2, i % 2 == 0) for i in range(100))

        _, transitions = drive(*steps)

        assert transitions.count(Transition.OPENED) == 1
        assert Transition.CLOSED not in transitions

    @given(pattern=st.lists(st.booleans(), min_size=1, max_size=400))
    def test_incidents_are_separated_by_at_least_the_recovery_period(
        self, pattern: list[bool]
    ) -> None:
        tracker = PressureTracker.idle()
        opened_at: list[datetime] = []
        closed_at: list[datetime] = []
        for index, above in enumerate(pattern):
            now = at(index * 2)
            tracker, transition = tracker.advance(now, above=above, policy=POLICY)
            if transition is Transition.OPENED:
                opened_at.append(now)
            if transition is Transition.CLOSED:
                closed_at.append(now)

        assert len(opened_at) - len(closed_at) in (0, 1)
        for close, reopen in zip(closed_at, opened_at[1:], strict=False):
            assert reopen - close >= POLICY.duration


class TestPolicy:
    def test_durations_are_validated(self) -> None:
        with pytest.raises(ValueError, match="duration"):
            LifecyclePolicy(duration=timedelta(0), recovery=timedelta(seconds=1))
        with pytest.raises(ValueError, match="recovery"):
            LifecyclePolicy(duration=timedelta(seconds=1), recovery=timedelta(seconds=-1))

    def test_a_backward_clock_step_keeps_the_elapsed_streak(self) -> None:
        # NTP or a VM resume moved the wall clock back an hour after 12 s of pressure.
        tracker, _ = drive((0, True), (12, True))

        tracker, transition = tracker.advance(at(12 - 3600), above=True, policy=POLICY)
        assert transition is Transition.NONE
        assert tracker.phase is Phase.SUSPECT
        assert tracker.last_observed == at(12 - 3600)

        # 8 more seconds complete the 20 s duration in the new timeline: no blind hour.
        tracker, transition = tracker.advance(at(20 - 3600), above=True, policy=POLICY)
        assert transition is Transition.OPENED
        assert tracker.since == at(-3600)

    def test_a_backward_step_during_recovery_keeps_the_recovery_elapsed(self) -> None:
        tracker, _ = drive((0, True), (20, True), (22, False), (40, False))

        tracker, _ = tracker.advance(at(40 - 600), above=False, policy=POLICY)
        tracker, transition = tracker.advance(at(52 - 600), above=False, policy=POLICY)

        assert transition is Transition.CLOSED
