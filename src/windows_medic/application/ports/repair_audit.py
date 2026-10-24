"""Durable repair audit as a capability."""

from datetime import datetime
from typing import Protocol

from windows_medic.domain.models.repair import RepairRecord


class RepairAuditRepository(Protocol):
    """Stores repair records by id; every operation is bounded and may raise RepairAuditError."""

    def save(self, record: RepairRecord) -> None:
        """Insert or replace *record* (with its members) atomically."""
        ...

    def get(self, repair_id: str) -> RepairRecord | None:
        """Load one record."""
        ...

    def recent(self, *, limit: int) -> tuple[RepairRecord, ...]:
        """At most *limit* records, newest ``requested_at`` first."""
        ...

    def purge_older_than(self, cutoff: datetime) -> int:
        """Delete records requested before *cutoff*."""
        ...
