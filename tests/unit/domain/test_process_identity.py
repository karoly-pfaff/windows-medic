"""ProcessIdentity: a process is (pid, create_time); PID alone is never an identity."""

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from windows_medic.domain.models.process import MAX_PID, ProcessIdentity

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)


class TestEquality:
    def test_same_pid_and_create_time_is_the_same_process(self) -> None:
        assert ProcessIdentity(1234, T0) == ProcessIdentity(1234, T0)
        assert hash(ProcessIdentity(1234, T0)) == hash(ProcessIdentity(1234, T0))

    def test_same_pid_with_different_create_time_is_a_different_process(self) -> None:
        original = ProcessIdentity(1234, T0)
        reused = ProcessIdentity(1234, T0 + timedelta(seconds=1))

        assert original != reused
        assert len({original, reused}) == 2

    def test_different_pid_with_same_create_time_is_a_different_process(self) -> None:
        assert ProcessIdentity(1, T0) != ProcessIdentity(2, T0)

    @given(
        pid=st.integers(min_value=0, max_value=2**31 - 1),
        delta_microseconds=st.integers(min_value=1, max_value=10**12),
    )
    def test_any_create_time_difference_makes_a_distinct_identity(
        self, pid: int, delta_microseconds: int
    ) -> None:
        later = T0 + timedelta(microseconds=delta_microseconds)

        assert ProcessIdentity(pid, T0) != ProcessIdentity(pid, later)

    def test_is_immutable(self) -> None:
        identity = ProcessIdentity(1, T0)

        with pytest.raises(AttributeError):
            identity.pid = 2  # type: ignore[misc]


class TestValidation:
    def test_negative_pid_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="pid"):
            ProcessIdentity(-1, T0)

    def test_a_pid_beyond_32_bits_is_rejected(self) -> None:
        assert ProcessIdentity(MAX_PID, T0).pid == 2**32 - 1
        with pytest.raises(ValueError, match="pid"):
            ProcessIdentity(MAX_PID + 1, T0)

    def test_naive_create_time_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            ProcessIdentity(1, datetime(2026, 9, 11, 12, 0, 0))  # noqa: DTZ001

    def test_pid_zero_is_allowed_for_the_idle_process(self) -> None:
        assert ProcessIdentity(0, T0).pid == 0


class TestRepresentation:
    def test_str_shows_pid_and_iso_create_time(self) -> None:
        assert str(ProcessIdentity(42, T0)) == "pid 42 @ 2026-09-11T12:00:00+00:00"
