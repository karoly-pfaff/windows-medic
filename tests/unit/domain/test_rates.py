"""Rates derived from pairs of cumulative observations, matched by exact identity."""

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from windows_medic.domain.models.metric import Unavailable, UnavailableReason, available
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.samples import CpuTimes
from windows_medic.domain.policies.rates import (
    bytes_per_second,
    process_cpu_percent,
    system_cpu_percent,
)

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(seconds=2)
IDENTITY = ProcessIdentity(100, T0 - timedelta(hours=1))


def observation(
    identity: ProcessIdentity = IDENTITY,
    observed_at: datetime = T0,
    cpu_time_seconds: float | Unavailable = 0.0,
    io_read_bytes: int | Unavailable = 0,
) -> ProcessObservation:
    return ProcessObservation(
        identity=identity,
        observed_at=observed_at,
        name="x.exe",
        exe_path=Unavailable(UnavailableReason.ACCESS_DENIED),
        command_line=(),
        parent_pid=1,
        username="user",
        session_id=1,
        cpu_time_seconds=cpu_time_seconds,
        working_set_bytes=0,
        private_bytes=0,
        io_read_bytes=io_read_bytes,
        io_write_bytes=0,
        thread_count=1,
        handle_count=1,
    )


class TestSystemCpuPercent:
    def test_busy_share_of_elapsed_cpu_time(self) -> None:
        before = CpuTimes(busy_seconds=10.0, total_seconds=100.0)
        after = CpuTimes(busy_seconds=15.0, total_seconds=110.0)

        assert system_cpu_percent(before, after) == 50.0

    def test_no_elapsed_cpu_time_is_inconsistent(self) -> None:
        times = CpuTimes(busy_seconds=10.0, total_seconds=100.0)

        assert system_cpu_percent(times, times) == Unavailable(UnavailableReason.INCONSISTENT)

    def test_counter_going_backwards_is_inconsistent(self) -> None:
        before = CpuTimes(busy_seconds=10.0, total_seconds=100.0)
        after = CpuTimes(busy_seconds=9.0, total_seconds=110.0)

        assert system_cpu_percent(before, after) == Unavailable(UnavailableReason.INCONSISTENT)

    def test_result_is_clamped_to_100(self) -> None:
        before = CpuTimes(busy_seconds=10.0, total_seconds=100.0)
        after = CpuTimes(busy_seconds=20.001, total_seconds=110.0)

        assert system_cpu_percent(before, after) == 100.0

    @given(
        busy_delta=st.floats(min_value=0.0, max_value=1000.0),
        idle_delta=st.floats(min_value=0.001, max_value=1000.0),
    )
    def test_any_advancing_counters_yield_a_bounded_percentage(
        self, busy_delta: float, idle_delta: float
    ) -> None:
        before = CpuTimes(busy_seconds=5.0, total_seconds=50.0)
        after = CpuTimes(
            busy_seconds=5.0 + busy_delta, total_seconds=50.0 + busy_delta + idle_delta
        )

        percent = system_cpu_percent(before, after)

        assert available(percent)
        assert 0.0 <= percent <= 100.0


class TestProcessCpuPercent:
    def test_cpu_time_delta_normalised_by_wall_time_and_cpu_count(self) -> None:
        before = observation(observed_at=T0, cpu_time_seconds=1.0)
        after = observation(observed_at=T1, cpu_time_seconds=2.0)

        # 1 s of CPU over 2 s of wall time on 4 logical CPUs = 12.5 % of the machine.
        assert process_cpu_percent(before, after, cpu_count=4) == 12.5

    def test_different_identity_is_a_programming_error(self) -> None:
        before = observation(identity=ProcessIdentity(100, T0), observed_at=T0)
        reused = ProcessIdentity(100, T0 + timedelta(seconds=1))
        after = observation(identity=reused, observed_at=T1)

        with pytest.raises(ValueError, match="identity"):
            process_cpu_percent(before, after, cpu_count=4)

    def test_unavailable_cpu_time_propagates_its_reason(self) -> None:
        denied = Unavailable(UnavailableReason.ACCESS_DENIED)
        before = observation(observed_at=T0, cpu_time_seconds=denied)
        after = observation(observed_at=T1, cpu_time_seconds=2.0)

        assert process_cpu_percent(before, after, cpu_count=4) == denied

    def test_latest_unavailability_wins_when_both_are_unavailable(self) -> None:
        before = observation(observed_at=T0, cpu_time_seconds=Unavailable(UnavailableReason.ERROR))
        after = observation(
            observed_at=T1, cpu_time_seconds=Unavailable(UnavailableReason.ACCESS_DENIED)
        )

        assert process_cpu_percent(before, after, cpu_count=4) == Unavailable(
            UnavailableReason.ACCESS_DENIED
        )

    def test_no_wall_time_elapsed_is_inconsistent(self) -> None:
        before = observation(observed_at=T0, cpu_time_seconds=1.0)
        after = observation(observed_at=T0, cpu_time_seconds=2.0)

        assert process_cpu_percent(before, after, cpu_count=4) == Unavailable(
            UnavailableReason.INCONSISTENT
        )

    def test_cpu_time_going_backwards_is_inconsistent(self) -> None:
        before = observation(observed_at=T0, cpu_time_seconds=2.0)
        after = observation(observed_at=T1, cpu_time_seconds=1.0)

        assert process_cpu_percent(before, after, cpu_count=4) == Unavailable(
            UnavailableReason.INCONSISTENT
        )

    def test_result_is_clamped_to_100(self) -> None:
        before = observation(observed_at=T0, cpu_time_seconds=0.0)
        after = observation(observed_at=T1, cpu_time_seconds=9.0)

        assert process_cpu_percent(before, after, cpu_count=4) == 100.0

    def test_cpu_count_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="cpu_count"):
            process_cpu_percent(observation(), observation(observed_at=T1), cpu_count=0)


class TestBytesPerSecond:
    def test_delta_over_elapsed_seconds(self) -> None:
        assert bytes_per_second(1_000, 5_000, T0, T1) == 2_000.0

    def test_unavailable_counter_propagates(self) -> None:
        gone = Unavailable(UnavailableReason.PROCESS_GONE)

        assert bytes_per_second(1_000, gone, T0, T1) == gone
        assert bytes_per_second(gone, 5_000, T0, T1) == gone

    def test_no_elapsed_time_is_inconsistent(self) -> None:
        assert bytes_per_second(1, 2, T0, T0) == Unavailable(UnavailableReason.INCONSISTENT)

    def test_counter_reset_is_inconsistent(self) -> None:
        assert bytes_per_second(5, 2, T0, T1) == Unavailable(UnavailableReason.INCONSISTENT)
