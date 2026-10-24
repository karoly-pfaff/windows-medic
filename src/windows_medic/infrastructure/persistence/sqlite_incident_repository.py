"""SQLite-backed :class:`IncidentRepository`.

Every write is one short ``BEGIN IMMEDIATE`` transaction with bounded busy retries
(see :mod:`sqlite_support`); failures become :class:`IncidentStoreError` so the caller
can degrade instead of crashing.
"""

from datetime import datetime

from windows_medic.application.ports.clock import Clock
from windows_medic.domain.errors import IncidentStoreError
from windows_medic.domain.models.incident import (
    Incident,
    IncidentKind,
    IncidentStatus,
    IncidentSummary,
    ProcessEvidenceSample,
    Severity,
    SystemEvidenceSample,
    interrupt_incident,
)
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.infrastructure.persistence.sqlite_connection import Database
from windows_medic.infrastructure.persistence.sqlite_support import (
    DEFAULT_RETRIES,
    DEFAULT_RETRY_DELAY_SECONDS,
    SqliteSupervisor,
    decode_float,
    decode_int,
    decode_str,
    encode,
    iso,
    iso_or_none,
    parse,
    parse_or_none,
)


class SqliteIncidentRepository:
    """Stores incidents and their bounded evidence in three tables."""

    def __init__(
        self,
        database: Database,
        *,
        clock: Clock,
        retries: int = DEFAULT_RETRIES,
        retry_delay_seconds: float = DEFAULT_RETRY_DELAY_SECONDS,
    ) -> None:
        self.connection = database.connection
        self._clock = clock
        self._db = SqliteSupervisor(
            database,
            error=IncidentStoreError,
            label="incident store",
            retries=retries,
            retry_delay_seconds=retry_delay_seconds,
        )

    # -- port ------------------------------------------------------------------------------

    def save(self, incident: Incident) -> None:
        self._db.transaction(lambda: self._write(incident))

    def get(self, incident_id: str) -> Incident | None:
        return self._db.retrying(lambda: self._read(incident_id))

    def recent(self, *, limit: int) -> tuple[IncidentSummary, ...]:
        return self._db.retrying(lambda: self._list(limit))

    def active_since(self, cutoff: datetime, *, limit: int) -> tuple[Incident, ...]:
        return self._db.retrying(lambda: self._active_since(cutoff, limit))

    def interrupt_unclosed(self) -> tuple[str, ...]:
        return self._db.transaction(self._interrupt_unclosed)

    def purge_older_than(self, cutoff: datetime) -> int:
        return self._db.transaction(lambda: self._purge(cutoff))

    # -- statements ------------------------------------------------------------------------

    def _write(self, incident: Incident) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO incidents (
                id, kind, status, severity, started_at, triggered_at, recovering_since,
                closed_at, threshold, peak, window_start, window_end, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident.id,
                incident.kind.value,
                incident.status.value,
                incident.severity.value,
                iso(incident.started_at),
                iso(incident.triggered_at),
                iso_or_none(incident.recovering_since),
                iso_or_none(incident.closed_at),
                incident.threshold,
                incident.peak,
                iso(incident.evidence_window[0]),
                iso(incident.evidence_window[1]),
                iso(self._clock.now()),
            ),
        )
        self.connection.execute(
            "DELETE FROM incident_system_samples WHERE incident_id = ?", (incident.id,)
        )
        self.connection.execute(
            "DELETE FROM incident_contributors WHERE incident_id = ?", (incident.id,)
        )
        self.connection.executemany(
            """
            INSERT INTO incident_system_samples (
                incident_id, position, observed_at, cpu_percent, cpu_percent_unavailable,
                memory_percent_used, memory_available_bytes, process_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    incident.id,
                    position,
                    iso(sample.observed_at),
                    *encode(sample.cpu_percent),
                    sample.memory_percent_used,
                    sample.memory_available_bytes,
                    sample.process_count,
                )
                for position, sample in enumerate(incident.system_evidence)
            ],
        )
        self.connection.executemany(
            """
            INSERT INTO incident_contributors (
                incident_id, position, pid, create_time,
                name, name_unavailable, exe_path, exe_path_unavailable,
                command_line, command_line_unavailable, cpu_percent, cpu_percent_unavailable,
                working_set_bytes, working_set_bytes_unavailable,
                private_bytes, private_bytes_unavailable
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    incident.id,
                    position,
                    sample.identity.pid,
                    iso(sample.identity.create_time),
                    *encode(sample.name),
                    *encode(sample.exe_path),
                    *encode(sample.command_line),
                    *encode(sample.cpu_percent),
                    *encode(sample.working_set_bytes),
                    *encode(sample.private_bytes),
                )
                for position, sample in enumerate(incident.contributors)
            ],
        )

    def _interrupt_unclosed(self) -> tuple[str, ...]:
        rows = self.connection.execute(
            "SELECT id, updated_at FROM incidents WHERE closed_at IS NULL"
        ).fetchall()
        interrupted: list[str] = []
        for incident_id, updated_at in rows:
            incident = self._read(incident_id)
            if incident is not None:
                self._write(interrupt_incident(incident, parse(updated_at)))
                interrupted.append(incident_id)
        return tuple(interrupted)

    def _read(self, incident_id: str) -> Incident | None:
        row = self.connection.execute(
            """
            SELECT id, kind, status, severity, started_at, triggered_at, recovering_since,
                   closed_at, threshold, peak, window_start, window_end
            FROM incidents WHERE id = ?
            """,
            (incident_id,),
        ).fetchone()
        if row is None:
            return None
        system_rows = self.connection.execute(
            """
            SELECT observed_at, cpu_percent, cpu_percent_unavailable, memory_percent_used,
                   memory_available_bytes, process_count
            FROM incident_system_samples WHERE incident_id = ? ORDER BY position
            """,
            (incident_id,),
        ).fetchall()
        contributor_rows = self.connection.execute(
            """
            SELECT pid, create_time, name, name_unavailable, exe_path, exe_path_unavailable,
                   command_line, command_line_unavailable, cpu_percent, cpu_percent_unavailable,
                   working_set_bytes, working_set_bytes_unavailable,
                   private_bytes, private_bytes_unavailable
            FROM incident_contributors WHERE incident_id = ? ORDER BY position
            """,
            (incident_id,),
        ).fetchall()
        return Incident(
            id=row[0],
            kind=IncidentKind(row[1]),
            status=IncidentStatus(row[2]),
            severity=Severity(row[3]),
            started_at=parse(row[4]),
            triggered_at=parse(row[5]),
            recovering_since=parse_or_none(row[6]),
            closed_at=parse_or_none(row[7]),
            threshold=float(row[8]),
            peak=float(row[9]),
            evidence_window=(parse(row[10]), parse(row[11])),
            system_evidence=tuple(
                SystemEvidenceSample(
                    observed_at=parse(r[0]),
                    cpu_percent=decode_float(r[1], r[2]),
                    memory_percent_used=float(r[3]),
                    memory_available_bytes=int(r[4]),
                    process_count=int(r[5]),
                )
                for r in system_rows
            ),
            contributors=tuple(
                ProcessEvidenceSample(
                    identity=ProcessIdentity(int(r[0]), parse(r[1])),
                    name=decode_str(r[2], r[3]),
                    exe_path=decode_str(r[4], r[5]),
                    command_line=decode_str(r[6], r[7]),
                    cpu_percent=decode_float(r[8], r[9]),
                    working_set_bytes=decode_int(r[10], r[11]),
                    private_bytes=decode_int(r[12], r[13]),
                )
                for r in contributor_rows
            ),
        )

    def _list(self, limit: int) -> tuple[IncidentSummary, ...]:
        rows = self.connection.execute(
            """
            SELECT id, kind, status, severity, started_at, triggered_at, closed_at, threshold, peak
            FROM incidents ORDER BY started_at DESC, id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return tuple(
            IncidentSummary(
                id=r[0],
                kind=IncidentKind(r[1]),
                status=IncidentStatus(r[2]),
                severity=Severity(r[3]),
                started_at=parse(r[4]),
                triggered_at=parse(r[5]),
                closed_at=parse_or_none(r[6]),
                threshold=float(r[7]),
                peak=float(r[8]),
            )
            for r in rows
        )

    def _active_since(self, cutoff: datetime, limit: int) -> tuple[Incident, ...]:
        rows = self.connection.execute(
            """
            SELECT id FROM incidents WHERE closed_at IS NULL OR closed_at >= ?
            ORDER BY started_at DESC, id DESC LIMIT ?
            """,
            (iso(cutoff), limit),
        ).fetchall()
        loaded = (self._read(row[0]) for row in rows)
        return tuple(incident for incident in loaded if incident is not None)

    def _purge(self, cutoff: datetime) -> int:
        cursor = self.connection.execute(
            "DELETE FROM incidents WHERE COALESCE(closed_at, started_at) < ?", (iso(cutoff),)
        )
        return int(cursor.rowcount)
