"""SystemClock adapter contract."""

import time
from datetime import UTC, datetime

from windows_medic.infrastructure.time.system_clock import SystemClock


def test_now_is_timezone_aware_utc_and_current() -> None:
    before = datetime.now(UTC)

    now = SystemClock().now()

    assert now.tzinfo is UTC
    assert before <= now <= datetime.now(UTC)


def test_sleep_blocks_for_at_least_the_requested_time() -> None:
    started = time.perf_counter()

    SystemClock().sleep(0.02)

    assert time.perf_counter() - started >= 0.02
