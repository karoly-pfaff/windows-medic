"""Instantaneous pressure signal and the adaptive sampling state machine."""

from datetime import UTC, datetime, timedelta

import pytest

from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.samples import MemoryObservation
from windows_medic.domain.policies.adaptive_sampling import (
    AdaptivePolicy,
    SamplingMode,
    SamplingState,
    advance,
)
from windows_medic.domain.policies.pressure import (
    PressureSignal,
    PressureThresholds,
    instant_pressure,
)

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)
GIB = 1024**3
THRESHOLDS = PressureThresholds(
    cpu_percent=90.0, memory_percent=90.0, memory_available_floor_bytes=int(1.5 * GIB)
)


def memory(used_fraction: float, total_gib: int = 32) -> MemoryObservation:
    total = total_gib * GIB
    return MemoryObservation(total_bytes=total, available_bytes=int(total * (1 - used_fraction)))


class TestInstantPressure:
    def test_calm_system_has_no_signal(self) -> None:
        signal = instant_pressure(cpu_percent=10.0, memory=memory(0.5), thresholds=THRESHOLDS)

        assert signal == PressureSignal(cpu=False, memory=False)
        assert signal.suspect is False

    def test_cpu_at_or_above_threshold_is_suspect(self) -> None:
        assert instant_pressure(90.0, memory(0.5), THRESHOLDS).cpu is True
        assert instant_pressure(89.9, memory(0.5), THRESHOLDS).cpu is False

    def test_memory_percent_at_or_above_threshold_is_suspect(self) -> None:
        assert instant_pressure(1.0, memory(0.9), THRESHOLDS).memory is True
        assert instant_pressure(1.0, memory(0.89), THRESHOLDS).memory is False

    def test_memory_available_below_floor_is_suspect_even_at_low_percent(self) -> None:
        tight = MemoryObservation(total_bytes=4 * GIB, available_bytes=1 * GIB)

        assert instant_pressure(1.0, tight, THRESHOLDS).memory is True

    def test_unavailable_cpu_is_not_a_signal(self) -> None:
        signal = instant_pressure(
            Unavailable(UnavailableReason.INCONSISTENT), memory(0.5), THRESHOLDS
        )

        assert signal.cpu is False

    def test_thresholds_are_validated(self) -> None:
        with pytest.raises(ValueError, match="cpu_percent"):
            PressureThresholds(cpu_percent=0, memory_percent=90, memory_available_floor_bytes=0)
        with pytest.raises(ValueError, match="memory_percent"):
            PressureThresholds(cpu_percent=90, memory_percent=101, memory_available_floor_bytes=0)
        with pytest.raises(ValueError, match="memory_available_floor_bytes"):
            PressureThresholds(cpu_percent=90, memory_percent=90, memory_available_floor_bytes=-1)


POLICY = AdaptivePolicy(escalation_max=timedelta(seconds=300), cooldown=timedelta(seconds=60))


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


class TestAdaptiveSampling:
    def test_starts_normal(self) -> None:
        state = SamplingState.initial(T0)

        assert state.mode is SamplingMode.NORMAL
        assert state.since == T0

    def test_suspect_escalates_immediately(self) -> None:
        state = advance(SamplingState.initial(T0), at(2), suspect=True, policy=POLICY)

        assert state == SamplingState(SamplingMode.ESCALATED, at(2))

    def test_calm_while_escalated_enters_cooldown(self) -> None:
        escalated = SamplingState(SamplingMode.ESCALATED, at(2))

        state = advance(escalated, at(4), suspect=False, policy=POLICY)

        assert state == SamplingState(SamplingMode.COOLDOWN, at(4))

    def test_escalation_is_bounded_even_under_sustained_pressure(self) -> None:
        escalated = SamplingState(SamplingMode.ESCALATED, at(0))

        still = advance(escalated, at(299), suspect=True, policy=POLICY)
        expired = advance(escalated, at(300), suspect=True, policy=POLICY)

        assert still is escalated
        assert expired == SamplingState(SamplingMode.COOLDOWN, at(300))

    def test_cooldown_ignores_pressure_until_it_expires(self) -> None:
        cooling = SamplingState(SamplingMode.COOLDOWN, at(0))

        assert advance(cooling, at(59), suspect=True, policy=POLICY) is cooling
        assert advance(cooling, at(60), suspect=True, policy=POLICY) == SamplingState(
            SamplingMode.NORMAL, at(60)
        )

    def test_after_cooldown_pressure_escalates_again_on_the_next_tick(self) -> None:
        cooled = advance(SamplingState(SamplingMode.COOLDOWN, at(0)), at(60), True, POLICY)

        assert advance(cooled, at(62), suspect=True, policy=POLICY).mode is SamplingMode.ESCALATED

    def test_normal_stays_normal_when_calm(self) -> None:
        state = SamplingState.initial(T0)

        assert advance(state, at(10), suspect=False, policy=POLICY) is state

    def test_policy_is_validated(self) -> None:
        with pytest.raises(ValueError, match="escalation_max"):
            AdaptivePolicy(escalation_max=timedelta(0), cooldown=timedelta(seconds=1))
        with pytest.raises(ValueError, match="cooldown"):
            AdaptivePolicy(escalation_max=timedelta(seconds=1), cooldown=timedelta(seconds=-1))

    def test_no_incident_storm_under_flapping_pressure(self) -> None:
        state = SamplingState.initial(T0)
        escalations = 0
        for tick in range(0, 1200, 2):
            previous = state.mode
            state = advance(state, at(tick), suspect=(tick // 4) % 2 == 0, policy=POLICY)
            if state.mode is SamplingMode.ESCALATED and previous is not SamplingMode.ESCALATED:
                escalations += 1

        # Flapping every 4 s for 20 min: each escalation is followed by a 60 s cool-down, so
        # there can be at most ~20 escalations rather than ~150.
        assert escalations <= 20
