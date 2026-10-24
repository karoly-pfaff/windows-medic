"""Real wall clock."""

import time
from datetime import UTC, datetime


class SystemClock:
    """:class:`windows_medic.application.ports.clock.Clock` backed by the OS clock."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
