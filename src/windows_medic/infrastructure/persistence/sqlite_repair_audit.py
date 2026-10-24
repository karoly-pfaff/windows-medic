"""SQLite-backed :class:`RepairAuditRepository`, sharing the incident database.

Records are written twice per repair (intended action, then outcome) as short
``BEGIN IMMEDIATE`` transactions with bounded busy retries; failures become
:class:`RepairAuditError`. Members and drift live in child tables that cascade on delete.
"""

from datetime import datetime

from windows_medic.domain.errors import RepairAuditError
from windows_medic.domain.models.process import ProcessIdentity
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
from windows_medic.infrastructure.persistence.sqlite_connection import Database
from windows_medic.infrastructure.persistence.sqlite_support import (
    DEFAULT_RETRIES,
    DEFAULT_RETRY_DELAY_SECONDS,
    SqliteSupervisor,
    decode_str,
    encode,
    iso,
    iso_or_none,
    parse,
    parse_or_none,
)

_SELECT = """
    SELECT id, action, scope, status, requested_at, completed_at, target_pid,
           target_create_time, port, risk, requires_elevation, rejection,
           verification_passed, verification_detail, verification_checked_at,
           replacement_pid, replacement_create_time
    FROM repairs
"""


class SqliteRepairAuditRepository:
    """Stores repair records, their members and identity drift in three tables."""

    def __init__(
        self,
        database: Database,
        *,
        retries: int = DEFAULT_RETRIES,
        retry_delay_seconds: float = DEFAULT_RETRY_DELAY_SECONDS,
    ) -> None:
        self.connection = database.connection
        self._db = SqliteSupervisor(
            database,
            error=RepairAuditError,
            label="repair audit",
            retries=retries,
            retry_delay_seconds=retry_delay_seconds,
        )

    # -- port ------------------------------------------------------------------------------

    def save(self, record: RepairRecord) -> None:
        self._db.transaction(lambda: self._write(record))

    def get(self, repair_id: str) -> RepairRecord | None:
        return self._db.retrying(lambda: self._read(repair_id))

    def recent(self, *, limit: int) -> tuple[RepairRecord, ...]:
        return self._db.retrying(lambda: self._recent(limit))

    def purge_older_than(self, cutoff: datetime) -> int:
        return self._db.transaction(lambda: self._purge(cutoff))

    # -- statements ------------------------------------------------------------------------

    def _write(self, record: RepairRecord) -> None:
        verification = record.verification
        self.connection.execute(
            """
            INSERT OR REPLACE INTO repairs (
                id, action, scope, status, requested_at, completed_at, target_pid,
                target_create_time, port, risk, requires_elevation, rejection,
                verification_passed, verification_detail, verification_checked_at,
                replacement_pid, replacement_create_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.id,
                record.action.value,
                record.scope.value,
                record.status.value,
                iso(record.requested_at),
                iso_or_none(record.completed_at),
                None if record.target is None else record.target.pid,
                None if record.target is None else iso(record.target.create_time),
                record.port,
                None if record.risk is None else record.risk.value,
                int(record.requires_elevation),
                None if record.rejection is None else record.rejection.value,
                None if verification is None else int(verification.passed),
                None if verification is None else verification.detail,
                None if verification is None else iso(verification.checked_at),
                None if record.replacement is None else record.replacement.pid,
                None if record.replacement is None else iso(record.replacement.create_time),
            ),
        )
        self.connection.execute("DELETE FROM repair_members WHERE repair_id = ?", (record.id,))
        self.connection.execute("DELETE FROM repair_appeared WHERE repair_id = ?", (record.id,))
        self.connection.executemany(
            """
            INSERT INTO repair_members (
                repair_id, position, pid, create_time, name, name_unavailable, depth,
                outcome, detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    record.id,
                    position,
                    member.identity.pid,
                    iso(member.identity.create_time),
                    *encode(member.name),
                    member.depth,
                    member.outcome.value,
                    member.detail,
                )
                for position, member in enumerate(record.members)
            ],
        )
        self.connection.executemany(
            "INSERT INTO repair_appeared (repair_id, position, pid, create_time) "
            "VALUES (?, ?, ?, ?)",
            [
                (record.id, position, identity.pid, iso(identity.create_time))
                for position, identity in enumerate(record.appeared)
            ],
        )

    def _read(self, repair_id: str) -> RepairRecord | None:
        row = self.connection.execute(_SELECT + " WHERE id = ?", (repair_id,)).fetchone()
        return None if row is None else self._hydrate(row)

    def _recent(self, limit: int) -> tuple[RepairRecord, ...]:
        rows = self.connection.execute(
            _SELECT + " ORDER BY requested_at DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
        return tuple(self._hydrate(row) for row in rows)

    def _purge(self, cutoff: datetime) -> int:
        cursor = self.connection.execute(
            "DELETE FROM repairs WHERE requested_at < ?", (iso(cutoff),)
        )
        return int(cursor.rowcount)

    def _hydrate(self, row: tuple[object, ...]) -> RepairRecord:
        repair_id = str(row[0])
        member_rows = self.connection.execute(
            """
            SELECT pid, create_time, name, name_unavailable, depth, outcome, detail
            FROM repair_members WHERE repair_id = ? ORDER BY position
            """,
            (repair_id,),
        ).fetchall()
        appeared_rows = self.connection.execute(
            "SELECT pid, create_time FROM repair_appeared WHERE repair_id = ? ORDER BY position",
            (repair_id,),
        ).fetchall()
        target = None if row[6] is None else ProcessIdentity(int(str(row[6])), parse(str(row[7])))
        verification = (
            None
            if row[12] is None
            else Verification(bool(row[12]), str(row[13]), parse(str(row[14])))
        )
        replacement = (
            None if row[15] is None else ProcessIdentity(int(str(row[15])), parse(str(row[16])))
        )
        return RepairRecord(
            id=repair_id,
            action=RepairAction(str(row[1])),
            scope=RepairScope(str(row[2])),
            status=RepairStatus(str(row[3])),
            requested_at=parse(str(row[4])),
            completed_at=parse_or_none(None if row[5] is None else str(row[5])),
            target=target,
            port=None if row[8] is None else int(str(row[8])),
            risk=None if row[9] is None else RiskLevel(str(row[9])),
            requires_elevation=bool(row[10]),
            rejection=None if row[11] is None else RejectionReason(str(row[11])),
            members=tuple(
                MemberResult(
                    identity=ProcessIdentity(int(r[0]), parse(r[1])),
                    name=decode_str(r[2], r[3]),
                    depth=int(r[4]),
                    outcome=MemberOutcome(r[5]),
                    detail=r[6],
                )
                for r in member_rows
            ),
            appeared=tuple(ProcessIdentity(int(r[0]), parse(r[1])) for r in appeared_rows),
            verification=verification,
            replacement=replacement,
        )
