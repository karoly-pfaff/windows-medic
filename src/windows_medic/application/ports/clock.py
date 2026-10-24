"""Time as a capability, so use cases stay deterministic under test."""

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    """Wall-clock time and bounded waiting."""

    def now(self) -> datetime:
        """Current time, timezone-aware (UTC)."""
        ...

    def sleep(self, seconds: float) -> None:
        """Block for *seconds*."""
        ...
