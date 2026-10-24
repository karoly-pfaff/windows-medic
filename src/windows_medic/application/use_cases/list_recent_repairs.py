"""List recent repair records, newest first, bounded."""

from dataclasses import dataclass

from windows_medic.application.ports.repair_audit import RepairAuditRepository
from windows_medic.domain.models.repair import RepairRecord

DEFAULT_LIMIT = 10


@dataclass(frozen=True, slots=True)
class RepairListLimits:
    max_limit: int

    def __post_init__(self) -> None:
        if self.max_limit < 1:
            raise ValueError("max_limit must be at least 1")


class ListRecentRepairs:
    def __init__(self, audit: RepairAuditRepository, limits: RepairListLimits) -> None:
        self._audit = audit
        self._limits = limits

    def execute(self, limit: int = DEFAULT_LIMIT) -> tuple[RepairRecord, ...]:
        """At most ``min(limit, max_limit)`` records, newest first.

        Raises:
            ValueError: If *limit* is not positive (a boundary bug).
            RepairAuditError: If the audit store cannot be read.
        """
        if limit < 1:
            raise ValueError(f"limit must be at least 1, got {limit}")
        return self._audit.recent(limit=min(limit, self._limits.max_limit))
