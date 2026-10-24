"""SQLite incident repository: WAL, migrations, round-trip, retention, bounded busy handling."""

import sqlite3
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.builders import BOOT, T0, identity
from tests.fakes import FakeClock
from windows_medic.domain.errors import IncidentStoreError
from windows_medic.domain.models.incident import (
    EvidenceLimits,
    Incident,
    IncidentKind,
    IncidentStatus,
    ProcessEvidenceSample,
    SystemEvidenceSample,
    begin_recovery,
    close_incident,
    open_incident,
)
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.infrastructure.persistence.migrations import SCHEMA_VERSION
from windows_medic.infrastructure.persistence.sqlite_connection import open_database
from windows_medic.infrastructure.persistence.sqlite_incident_repository import (
    SqliteIncidentRepository,
)

LIMITS = EvidenceLimits(
    max_system_samples=100, max_contributors=10, high_severity_after=timedelta(seconds=120)
)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def full_incident(number: int = 1, *, started: datetime = T0) -> Incident:
    denied = Unavailable(UnavailableReason.ACCESS_DENIED)
    return open_incident(
        incident_id=f"inc-{number}",
        kind=IncidentKind.CPU_PRESSURE,
        started_at=started,
        triggered_at=started + timedelta(seconds=20),
        threshold=90.0,
        pre_trigger=(
            SystemEvidenceSample(started - timedelta(seconds=2), 95.5, 60.0, 8 * 1024**3, 310),
            SystemEvidenceSample(
                started, Unavailable(UnavailableReason.INCONSISTENT), 61.0, 7 * 1024**3, 311
            ),
        ),
        contributors=(
            ProcessEvidenceSample(
                identity(100), "node.exe", "C:\\bin\\node.exe", "node build", 42.5, 512, 400
            ),
            ProcessEvidenceSample(
                identity(200, BOOT + timedelta(seconds=1)),
                "System",
                denied,
                denied,
                Unavailable(UnavailableReason.NO_BASELINE),
                denied,
                denied,
            ),
        ),
        evidence_window=(started - timedelta(seconds=60), started),
        limits=LIMITS,
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "data" / "incidents.sqlite3"


@pytest.fixture
def repository(db_path: Path) -> Iterator[SqliteIncidentRepository]:
    database = open_database(db_path)
    try:
        yield SqliteIncidentRepository(database, clock=FakeClock(T0))
    finally:
        database.close()


class TestDatabaseSetup:
    def test_creates_the_file_and_parent_directory_in_wal_mode(self, db_path: Path) -> None:
        database = open_database(db_path)
        try:
            journal = database.connection.execute("PRAGMA journal_mode").fetchone()[0]
            foreign_keys = database.connection.execute("PRAGMA foreign_keys").fetchone()[0]
        finally:
            database.close()

        assert db_path.is_file()
        assert journal == "wal"
        assert foreign_keys == 1

    def test_migrations_are_applied_once_and_are_idempotent(self, db_path: Path) -> None:
        for _ in range(2):
            database = open_database(db_path)
            try:
                versions = [
                    row[0]
                    for row in database.connection.execute(
                        "SELECT version FROM schema_version ORDER BY 1"
                    )
                ]
            finally:
                database.close()

        assert versions == list(range(1, SCHEMA_VERSION + 1))


class TestRoundTrip:
    def test_saved_incident_is_read_back_identically(
        self, repository: SqliteIncidentRepository
    ) -> None:
        incident = full_incident()

        repository.save(incident)

        assert repository.get("inc-1") == incident

    def test_unknown_id_is_none(self, repository: SqliteIncidentRepository) -> None:
        assert repository.get("nope") is None

    def test_saving_again_replaces_the_row_and_its_evidence(
        self, repository: SqliteIncidentRepository
    ) -> None:
        incident = full_incident()
        repository.save(incident)
        closed = close_incident(begin_recovery(incident, at(60)), at(90), LIMITS)

        repository.save(closed)

        assert repository.get("inc-1") == closed
        summaries = repository.recent(limit=10)
        assert len(summaries) == 1
        assert summaries[0].status is IncidentStatus.CLOSED

    def test_history_survives_reopening_the_database(self, db_path: Path) -> None:
        first = open_database(db_path)
        SqliteIncidentRepository(first, clock=FakeClock(T0)).save(full_incident())
        first.close()

        second = open_database(db_path)
        try:
            assert SqliteIncidentRepository(second, clock=FakeClock(T0)).get("inc-1") == (
                full_incident()
            )
        finally:
            second.close()


class TestListing:
    def test_recent_is_newest_first_and_bounded(self, repository: SqliteIncidentRepository) -> None:
        for number in range(5):
            repository.save(full_incident(number, started=T0 + timedelta(minutes=number)))

        summaries = repository.recent(limit=3)

        assert [s.id for s in summaries] == ["inc-4", "inc-3", "inc-2"]
        assert summaries[0].peak == 95.5
        assert summaries[0].closed_at is None


class TestActiveSince:
    def test_returns_full_incidents_open_at_any_point_since_the_cutoff(
        self, repository: SqliteIncidentRepository
    ) -> None:
        closed_before = close_incident(
            begin_recovery(full_incident(1, started=at(-7200)), at(-7100)), at(-7000), LIMITS
        )
        closed_after = close_incident(
            begin_recovery(full_incident(2, started=at(-7200)), at(-3000)), at(-2900), LIMITS
        )
        still_open = full_incident(3, started=at(-6000))
        newest = full_incident(4, started=at(-100))
        for incident in (closed_before, closed_after, still_open, newest):
            repository.save(incident)

        active = repository.active_since(at(-3600), limit=10)

        assert [i.id for i in active] == ["inc-4", "inc-3", "inc-2"]
        assert active[0].contributors[0].name == "node.exe"
        assert len(active[0].system_evidence) == 2

    def test_is_bounded_newest_first(self, repository: SqliteIncidentRepository) -> None:
        for number in range(5):
            repository.save(full_incident(number, started=T0 + timedelta(minutes=number)))

        active = repository.active_since(T0 - timedelta(hours=1), limit=2)

        assert [i.id for i in active] == ["inc-4", "inc-3"]


class TestInterruption:
    def test_unclosed_incidents_end_at_their_last_write(self, db_path: Path) -> None:
        clock = FakeClock(at(-100))
        database = open_database(db_path)
        try:
            repository = SqliteIncidentRepository(database, clock=clock)
            repository.save(full_incident(1, started=at(-300)))  # last written at -100
            clock.sleep(50)
            repository.save(begin_recovery(full_incident(2, started=at(-300)), at(-60)))
            closed = close_incident(
                begin_recovery(full_incident(3, started=at(-300)), at(-80)), at(-60), LIMITS
            )
            repository.save(closed)
            clock.sleep(3600)  # the agent was gone for an hour

            interrupted = repository.interrupt_unclosed()

            assert sorted(interrupted) == ["inc-1", "inc-2"]
            first, second = repository.get("inc-1"), repository.get("inc-2")
            assert first is not None
            assert second is not None
            assert first.status is IncidentStatus.INTERRUPTED
            assert first.closed_at == at(-100)
            assert second.status is IncidentStatus.INTERRUPTED
            assert second.closed_at == at(-50)
            assert second.recovering_since == at(-60)
            assert repository.get("inc-3") == closed
            # Interrupted incidents age out of lookbacks like closed ones.
            assert {i.id for i in repository.active_since(at(-90), limit=10)} == {
                "inc-2",
                "inc-3",
            }
            assert repository.interrupt_unclosed() == ()
        finally:
            database.close()


class TestRetention:
    def test_purges_incidents_that_ended_before_the_cutoff(
        self, repository: SqliteIncidentRepository
    ) -> None:
        old_closed = close_incident(
            begin_recovery(full_incident(1, started=at(-7200)), at(-7100)), at(-7000), LIMITS
        )
        old_open = full_incident(2, started=at(-7200))
        recent_closed = close_incident(
            begin_recovery(full_incident(3, started=at(-7200)), at(-100)), at(-50), LIMITS
        )
        recent_open = full_incident(4, started=at(-100))
        for incident in (old_closed, old_open, recent_closed, recent_open):
            repository.save(incident)

        removed = repository.purge_older_than(at(-3600))

        assert removed == 2
        assert {s.id for s in repository.recent(limit=10)} == {"inc-3", "inc-4"}
        assert repository.get("inc-1") is None
        orphaned = repository.connection.execute(
            "SELECT COUNT(*) FROM incident_system_samples WHERE incident_id = 'inc-1'"
        ).fetchone()[0]
        assert orphaned == 0


class TestBusyHandling:
    def test_a_locked_database_fails_within_bounded_time_not_forever(self, db_path: Path) -> None:
        database = open_database(db_path, busy_timeout_ms=50)
        repository = SqliteIncidentRepository(
            database, clock=FakeClock(T0), retries=2, retry_delay_seconds=0.05
        )
        blocker = sqlite3.connect(db_path, isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            started = time.perf_counter()
            with pytest.raises(IncidentStoreError, match="locked"):
                repository.save(full_incident())
            elapsed = time.perf_counter() - started
        finally:
            blocker.execute("ROLLBACK")
            blocker.close()

        assert elapsed < 3.0
        repository.save(full_incident())
        assert repository.get("inc-1") is not None
        database.close()

    def test_non_transient_errors_are_wrapped_without_retrying(self, db_path: Path) -> None:
        database = open_database(db_path)
        repository = SqliteIncidentRepository(database, clock=FakeClock(T0))
        database.connection.execute("DROP TABLE incident_contributors")

        with pytest.raises(IncidentStoreError):
            repository.save(full_incident())
        database.close()

    def test_a_closed_store_reports_a_store_error(self, db_path: Path) -> None:
        database = open_database(db_path)
        repository = SqliteIncidentRepository(database, clock=FakeClock(T0))
        database.close()

        with pytest.raises(IncidentStoreError, match="closed"):
            repository.recent(limit=1)


def test_timestamps_round_trip_with_timezone(repository: SqliteIncidentRepository) -> None:
    started = datetime(2026, 3, 1, 23, 59, 59, 123456, tzinfo=UTC)
    repository.save(full_incident(9, started=started))

    loaded = repository.get("inc-9")

    assert loaded is not None
    assert loaded.started_at == started
    assert loaded.started_at.tzinfo is not None
