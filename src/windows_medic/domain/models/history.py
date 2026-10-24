"""Bounded rolling history.

A :class:`RingBuffer` keeps the newest items only: nothing older than ``window`` before the
newest timestamp it has seen, and never more than ``max_items``. Eviction is driven by item
timestamps, not by a clock, so it is deterministic and testable. ``latest()`` is the item
with the newest timestamp; ``items()`` preserves insertion order.
"""

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class Retention:
    window: timedelta
    max_items: int

    def __post_init__(self) -> None:
        if self.window <= timedelta(0):
            raise ValueError("window must be positive")
        if self.max_items < 1:
            raise ValueError("max_items must be at least 1")


class RingBuffer[T]:
    """Newest-``window``/``max_items`` items, evicted deterministically on append."""

    def __init__(self, retention: Retention, *, timestamp: Callable[[T], datetime]) -> None:
        self._retention = retention
        self._timestamp = timestamp
        self._items: deque[T] = deque()
        self._newest: datetime | None = None

    def __len__(self) -> int:
        return len(self._items)

    def append(self, item: T) -> None:
        at = self._timestamp(item)
        if self._newest is None or at > self._newest:
            self._newest = at
        cutoff = self._newest - self._retention.window
        if at < cutoff:
            return
        self._items.append(item)
        self.evict_before(cutoff)
        while len(self._items) > self._retention.max_items:
            # Drop the oldest *timestamp*, not the oldest insertion, so a late-arriving old
            # item can never push out newer evidence.
            oldest = min(range(len(self._items)), key=lambda i: self._timestamp(self._items[i]))
            del self._items[oldest]

    def evict_before(self, cutoff: datetime) -> None:
        """Drop every item whose timestamp is before *cutoff*."""
        kept = [item for item in self._items if self._timestamp(item) >= cutoff]
        if len(kept) != len(self._items):
            self._items = deque(kept)

    def items(self) -> tuple[T, ...]:
        return tuple(self._items)

    def since(self, cutoff: datetime) -> tuple[T, ...]:
        return tuple(item for item in self._items if self._timestamp(item) >= cutoff)

    def latest(self) -> T | None:
        if not self._items:
            return None
        return max(self._items, key=self._timestamp)
