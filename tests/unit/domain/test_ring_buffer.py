"""RingBuffer: bounded by time window and item count; eviction is deterministic."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from windows_medic.domain.models.history import Retention, RingBuffer

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class Sample:
    at: datetime
    value: int


def buffer(window_seconds: float = 60.0, max_items: int = 100) -> RingBuffer[Sample]:
    retention = Retention(window=timedelta(seconds=window_seconds), max_items=max_items)
    return RingBuffer(retention, timestamp=lambda s: s.at)


def sample(seconds: float, value: int = 0) -> Sample:
    return Sample(T0 + timedelta(seconds=seconds), value)


class TestRetentionValidation:
    def test_window_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="window"):
            Retention(window=timedelta(0), max_items=1)

    def test_max_items_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="max_items"):
            Retention(window=timedelta(seconds=1), max_items=0)


class TestAppend:
    def test_keeps_items_in_insertion_order(self) -> None:
        ring = buffer()
        ring.append(sample(0, 1))
        ring.append(sample(1, 2))

        assert [s.value for s in ring.items()] == [1, 2]
        assert ring.latest() == sample(1, 2)
        assert len(ring) == 2

    def test_empty_buffer(self) -> None:
        ring = buffer()

        assert ring.items() == ()
        assert ring.latest() is None
        assert len(ring) == 0

    def test_evicts_items_older_than_the_window_relative_to_the_newest_item(self) -> None:
        ring = buffer(window_seconds=10)
        for seconds in (0, 5, 10, 11):
            ring.append(sample(seconds))

        assert [s.at for s in ring.items()] == [sample(5).at, sample(10).at, sample(11).at]

    def test_item_exactly_at_the_window_edge_is_kept(self) -> None:
        ring = buffer(window_seconds=10)
        ring.append(sample(0))
        ring.append(sample(10))

        assert len(ring) == 2

    def test_evicts_oldest_when_over_the_item_limit(self) -> None:
        ring = buffer(max_items=3)
        for seconds in range(5):
            ring.append(sample(seconds, seconds))

        assert [s.value for s in ring.items()] == [2, 3, 4]

    def test_item_older_than_the_window_of_the_newest_is_not_retained(self) -> None:
        ring = buffer(window_seconds=10)
        ring.append(sample(20))
        ring.append(sample(5))

        assert [s.at for s in ring.items()] == [sample(20).at]
        assert ring.latest() == sample(20)

    def test_item_cap_evicts_the_oldest_timestamp_not_the_oldest_insertion(self) -> None:
        ring = buffer(window_seconds=10, max_items=1)
        ring.append(sample(1))
        ring.append(sample(0))

        assert ring.items() == (sample(1),)
        assert ring.latest() == sample(1)


class TestQueries:
    def test_since_returns_items_at_or_after_the_cutoff(self) -> None:
        ring = buffer()
        for seconds in (0, 10, 20):
            ring.append(sample(seconds, seconds))

        assert [s.value for s in ring.since(T0 + timedelta(seconds=10))] == [10, 20]

    def test_evict_before_drops_older_items_deterministically(self) -> None:
        ring = buffer()
        for seconds in (0, 10, 20):
            ring.append(sample(seconds, seconds))

        ring.evict_before(T0 + timedelta(seconds=10))

        assert [s.value for s in ring.items()] == [10, 20]

    def test_items_returns_a_snapshot_not_a_live_view(self) -> None:
        ring = buffer()
        ring.append(sample(0))
        frozen = ring.items()
        ring.append(sample(1))

        assert len(frozen) == 1


class TestBounds:
    @given(
        offsets=st.lists(st.floats(min_value=0, max_value=1000), min_size=1, max_size=200),
        window=st.floats(min_value=0.001, max_value=100),
        max_items=st.integers(min_value=1, max_value=50),
    )
    def test_never_exceeds_either_bound_and_stays_ordered(
        self, offsets: list[float], window: float, max_items: int
    ) -> None:
        ring = buffer(window_seconds=window, max_items=max_items)
        newest = T0
        for offset in offsets:
            item = sample(offset)
            ring.append(item)
            newest = max(newest, item.at)
            assert len(ring) <= max_items
            assert all(s.at >= newest - timedelta(seconds=window) for s in ring.items())
        latest = ring.latest()
        assert latest is not None
        assert latest.at == newest
