"""Durable incident storage as a capability."""

from datetime import datetime
from typing import Protocol

from windows_medic.domain.models.incident import Incident, IncidentSummary


class IncidentRepository(Protocol):
    """Stores incidents by id; every operation is bounded and may raise IncidentStoreError."""

    def save(self, incident: Incident) -> None:
        """Insert or replace *incident* (with its evidence) atomically."""
        ...

    def get(self, incident_id: str) -> Incident | None:
        """Load one incident with its evidence."""
        ...

    def recent(self, *, limit: int) -> tuple[IncidentSummary, ...]:
        """At most *limit* summaries, newest ``started_at`` first."""
        ...

    def active_since(self, cutoff: datetime, *, limit: int) -> tuple[Incident, ...]:
        """At most *limit* full incidents that were open at any point since *cutoff*.

        That is: still open, or closed at or after *cutoff*. Newest ``started_at`` first.
        """
        ...

    def interrupt_unclosed(self) -> tuple[str, ...]:
        """Mark every incident that is not closed as interrupted, ending at its last write.

        Only the single agent of a data directory may call this, before it opens incidents
        of its own: anything still unclosed then was left behind by a previous run.
        Returns the ids it changed.
        """
        ...

    def purge_older_than(self, cutoff: datetime) -> int:
        """Delete incidents that ended (or started, if never closed) before *cutoff*."""
        ...
