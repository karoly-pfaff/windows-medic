"""Bounded, newest-first listing of persisted incidents."""

from dataclasses import dataclass

from windows_medic.application.ports.incident_repository import IncidentRepository
from windows_medic.domain.models.incident import IncidentSummary

DEFAULT_LIMIT = 10


@dataclass(frozen=True, slots=True)
class IncidentListLimits:
    max_limit: int

    def __post_init__(self) -> None:
        if self.max_limit < 1:
            raise ValueError("max_limit must be at least 1")


class ListRecentIncidents:
    def __init__(self, repository: IncidentRepository, limits: IncidentListLimits) -> None:
        self._repository = repository
        self._limits = limits

    def execute(self, limit: int = DEFAULT_LIMIT) -> tuple[IncidentSummary, ...]:
        """Return up to ``min(limit, max_limit)`` summaries, newest first."""
        if limit < 1:
            raise ValueError(f"limit must be positive, got {limit}")
        return self._repository.recent(limit=min(limit, self._limits.max_limit))
