"""Top-N contributor ranking is bounded and fully deterministic."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.policies.contributors import rank_top

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class Item:
    identity: ProcessIdentity
    value: Metric[float]


def item(pid: int, value: Metric[float], created: datetime = T0) -> Item:
    return Item(ProcessIdentity(pid, created), value)


def rank(items: list[Item], limit: int = 3) -> list[int]:
    ranked = rank_top(items, metric=lambda i: i.value, identity=lambda i: i.identity, limit=limit)
    return [i.identity.pid for i in ranked]


class TestOrdering:
    def test_orders_by_metric_descending(self) -> None:
        assert rank([item(1, 5.0), item(2, 50.0), item(3, 0.5)]) == [2, 1, 3]

    def test_ties_break_by_pid_ascending(self) -> None:
        assert rank([item(9, 1.0), item(3, 1.0), item(5, 1.0)]) == [3, 5, 9]

    def test_ties_on_pid_break_by_create_time_ascending(self) -> None:
        older = item(7, 1.0, T0)
        newer = item(7, 1.0, T0 + timedelta(seconds=1))

        assert rank_top(
            [newer, older], metric=lambda i: i.value, identity=lambda i: i.identity, limit=2
        ) == (older, newer)


class TestBounds:
    def test_result_is_limited(self) -> None:
        items = [item(pid, float(pid)) for pid in range(1, 11)]

        assert rank(items, limit=3) == [10, 9, 8]

    def test_limit_zero_yields_nothing(self) -> None:
        assert rank([item(1, 1.0)], limit=0) == []

    def test_negative_limit_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="limit"):
            rank([], limit=-1)


class TestUnavailable:
    def test_unavailable_metrics_are_not_ranked(self) -> None:
        items = [item(1, Unavailable(UnavailableReason.ACCESS_DENIED)), item(2, 0.0)]

        assert rank(items) == [2]


class TestDeterminism:
    @given(
        values=st.lists(
            st.tuples(st.integers(min_value=0, max_value=50), st.floats(0.0, 100.0)),
            max_size=30,
            unique_by=lambda pair: pair[0],
        ),
        limit=st.integers(min_value=0, max_value=10),
    )
    def test_output_is_bounded_sorted_and_independent_of_input_order(
        self, values: list[tuple[int, float]], limit: int
    ) -> None:
        items = [item(pid, value) for pid, value in values]

        forward = rank_top(
            items, metric=lambda i: i.value, identity=lambda i: i.identity, limit=limit
        )
        backward = rank_top(
            list(reversed(items)),
            metric=lambda i: i.value,
            identity=lambda i: i.identity,
            limit=limit,
        )

        assert forward == backward
        assert len(forward) <= limit
        assert set(forward) <= set(items)
        ranked_values = [i.value for i in forward if isinstance(i.value, float)]
        assert ranked_values == sorted(ranked_values, reverse=True)
