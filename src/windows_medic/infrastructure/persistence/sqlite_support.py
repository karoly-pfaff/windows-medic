"""Shared SQLite adapter mechanics: bounded retries, short transactions, value codecs.

Both repositories (incidents, repair audit) live in the same database and follow the same
rules: every write is one short ``BEGIN IMMEDIATE`` transaction; transient
``locked``/``busy`` errors are retried a bounded number of times; anything else (and
exhaustion) becomes the repository's own explicit error so callers can degrade.
"""

import sqlite3
import time
from collections.abc import Callable
from datetime import datetime

from windows_medic.domain.errors import WindowsMedicError
from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason
from windows_medic.infrastructure.persistence.sqlite_connection import Database

DEFAULT_RETRIES = 3
DEFAULT_RETRY_DELAY_SECONDS = 0.05
_TRANSIENT_MARKERS = ("locked", "busy")


class SqliteSupervisor:
    """Runs statements against one database, serialised, with bounded busy retries."""

    def __init__(
        self,
        database: Database,
        *,
        error: type[WindowsMedicError],
        label: str,
        retries: int = DEFAULT_RETRIES,
        retry_delay_seconds: float = DEFAULT_RETRY_DELAY_SECONDS,
    ) -> None:
        self.connection = database.connection
        self._lock = database.lock
        self._error = error
        self._label = label
        self._retries = retries
        self._retry_delay = retry_delay_seconds

    def transaction[T](self, work: Callable[[], T]) -> T:
        def run() -> T:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                result = work()
                self.connection.execute("COMMIT")
            except BaseException:
                self.connection.execute("ROLLBACK")
                raise
            return result

        return self.retrying(run)

    def retrying[T](self, work: Callable[[], T]) -> T:
        with self._lock:
            return self._retrying(work)

    def _retrying[T](self, work: Callable[[], T]) -> T:
        attempt = 0
        while True:
            try:
                return work()
            except sqlite3.OperationalError as exc:
                transient = any(marker in str(exc).lower() for marker in _TRANSIENT_MARKERS)
                attempt += 1
                if not transient or attempt > self._retries:
                    raise self._error(
                        f"{self._label} failed after {attempt} attempt(s): {exc}"
                    ) from exc
                time.sleep(self._retry_delay)
            except sqlite3.Error as exc:
                raise self._error(f"{self._label} failed: {exc}") from exc


def iso(value: datetime) -> str:
    return value.isoformat()


def iso_or_none(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def parse_or_none(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def encode[T](metric: Metric[T]) -> tuple[T | None, str | None]:
    """A metric as ``(value, unavailable_reason)`` columns."""
    if isinstance(metric, Unavailable):
        return None, metric.reason.value
    return metric, None


def decode_float(value: object, reason: object) -> Metric[float]:
    if reason is not None:
        return Unavailable(UnavailableReason(str(reason)))
    return float(value) if isinstance(value, (int, float)) else Unavailable(UnavailableReason.ERROR)


def decode_int(value: object, reason: object) -> Metric[int]:
    if reason is not None:
        return Unavailable(UnavailableReason(str(reason)))
    return int(value) if isinstance(value, int) else Unavailable(UnavailableReason.ERROR)


def decode_str(value: object, reason: object) -> Metric[str]:
    if reason is not None:
        return Unavailable(UnavailableReason(str(reason)))
    return value if isinstance(value, str) else Unavailable(UnavailableReason.ERROR)
