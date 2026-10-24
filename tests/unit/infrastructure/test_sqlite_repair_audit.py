"""SQLite-backed repair audit: records with members and drift round-trip, bounded listing."""

import sqlite3
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.builders import BOOT, T0, identity
from windows_medic.domain.errors import RepairAuditError
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.repair import (
    MemberOutcome,
    MemberResult,
    RejectionReason,
    RepairAction,
    RepairRecord,
    RepairScope,
    RepairStatus,
    RiskLevel,
    Verification,
)
from windows_medic.infrastructure.persistence.migrations import SCHEMA_VERSION
from windows_medic.infrastructure.persistence.sqlite_connection import open_database
from windows_medic.infrastructure.persistence.sqlite_repair_audit import (
    SqliteRepairAuditRepository,
)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def succeeded(number: int = 1, *, requested_at: datetime = T0) -> RepairRecord:
    return RepairRecord(
        id=f"rep-{number}",
        action=RepairAction.PROCESS_TERMINATE_TREE,
        scope=RepairScope.TREE,
        status=RepairStatus.PARTIAL,
        requested_at=requested_at,
        completed_at=requested_at + timedelta(seconds=2),
        target=identity(10),
        port=None,
        risk=RiskLevel.MEDIUM,
        requires_elevation=False,
        rejection=None,
        members=(
            MemberResult(identity(12), "node.exe", 2, MemberOutcome.TERMINATED, None),
            MemberResult(
                identity(11),
                Unavailable(UnavailableReason.ACCESS_DENIED),
                1,
                MemberOutcome.ACCESS_DENIED,
                "access is denied",
            ),
            MemberResult(identity(10), "node.exe", 0, MemberOutcome.TERMINATED, None),
        ),
        appeared=(identity(13, BOOT + timedelta(hours=1)),),
        verification=Verification(False, "2 of 3 members gone; still running: pid 11", at(2)),
        replacement=identity(14, BOOT + timedelta(hours=2)),
    )


def rejected(number: int = 2, *, requested_at: datetime = T0) -> RepairRecord:
    return RepairRecord(
        id=f"rep-{number}",
        action=RepairAction.PORT_CLEAR,
        scope=RepairScope.PROCESS,
        status=RepairStatus.REJECTED,
        requested_at=requested_at,
        completed_at=requested_at,
        target=None,
        port=3000,
        risk=None,
        requires_elevation=False,
        rejection=RejectionReason.PORT_NOT_LISTENING,
        members=(),
        appeared=(),
        verification=None,
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "data" / "incidents.sqlite3"


@pytest.fixture
def audit(db_path: Path) -> Iterator[SqliteRepairAuditRepository]:
    database = open_database(db_path)
    try:
        yield SqliteRepairAuditRepository(database)
    finally:
        database.close()


def test_the_schema_now_has_two_migrations(db_path: Path) -> None:
    database = open_database(db_path)
    try:
        tables = {
            row[0]
            for row in database.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    finally:
        database.close()

    assert SCHEMA_VERSION == 3
    assert {"repairs", "repair_members", "repair_appeared"} <= tables


def test_a_record_round_trips_with_members_and_drift(audit: SqliteRepairAuditRepository) -> None:
    record = succeeded()

    audit.save(record)

    assert audit.get("rep-1") == record


def test_a_rejection_round_trips(audit: SqliteRepairAuditRepository) -> None:
    audit.save(rejected())

    assert audit.get("rep-2") == rejected()


def test_saving_again_replaces_the_record_and_its_members(
    audit: SqliteRepairAuditRepository,
) -> None:
    started = RepairRecord(
        id="rep-1",
        action=RepairAction.PROCESS_TERMINATE_TREE,
        scope=RepairScope.TREE,
        status=RepairStatus.STARTED,
        requested_at=T0,
        completed_at=None,
        target=identity(10),
        port=None,
        risk=RiskLevel.MEDIUM,
        requires_elevation=False,
        rejection=None,
        members=(),
        appeared=(),
        verification=None,
    )
    audit.save(started)
    assert audit.get("rep-1") == started

    audit.save(succeeded())

    assert audit.get("rep-1") == succeeded()
    assert audit.connection.execute("SELECT COUNT(*) FROM repair_members").fetchone()[0] == 3


def test_unknown_id_is_none(audit: SqliteRepairAuditRepository) -> None:
    assert audit.get("nope") is None


def test_recent_is_newest_first_and_bounded(audit: SqliteRepairAuditRepository) -> None:
    for number in range(5):
        audit.save(rejected(number, requested_at=at(number)))

    records = audit.recent(limit=3)

    assert [r.id for r in records] == ["rep-4", "rep-3", "rep-2"]


def test_purge_removes_old_records_with_their_members(
    audit: SqliteRepairAuditRepository,
) -> None:
    audit.save(succeeded(1, requested_at=at(-7200)))
    audit.save(succeeded(2, requested_at=at(-10)))

    removed = audit.purge_older_than(at(-3600))

    assert removed == 1
    assert [r.id for r in audit.recent(limit=10)] == ["rep-2"]
    assert audit.connection.execute("SELECT COUNT(*) FROM repair_members").fetchone()[0] == 3


def test_a_locked_database_fails_within_bounded_time(db_path: Path) -> None:
    database = open_database(db_path, busy_timeout_ms=50)
    audit = SqliteRepairAuditRepository(database, retries=2, retry_delay_seconds=0.05)
    blocker = sqlite3.connect(db_path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(RepairAuditError, match="locked"):
            audit.save(rejected())
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
        database.close()


def test_a_closed_store_reports_an_audit_error(db_path: Path) -> None:
    database = open_database(db_path)
    audit = SqliteRepairAuditRepository(database)
    database.close()

    with pytest.raises(RepairAuditError, match="closed"):
        audit.recent(limit=1)
