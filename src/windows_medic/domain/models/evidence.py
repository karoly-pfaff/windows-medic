"""Evidence items: the observed facts a finding or repair candidate is built from.

Each item names *what kind* of fact it is (closed vocabulary), carries the measured value
and window when there is one, and points at the process or incident it came from. The
``detail`` string is a compact, deterministic rendering of those fields for humans; it is
never the source of truth.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from windows_medic.domain.models.process import ProcessIdentity


class EvidenceKind(StrEnum):
    INCIDENT = "incident"
    CURRENT_PRESSURE = "current_pressure"
    INCIDENT_CONTRIBUTION = "incident_contribution"
    CURRENT_CONTRIBUTION = "current_contribution"
    UNRESOLVED_PARENT = "unresolved_parent"
    DEVELOPMENT_CLASSIFIER = "development_classifier"
    PROCESS_AGE = "process_age"
    TREE_MEMBERS = "tree_members"
    RISK_MARKER = "risk_marker"
    PROTECTION = "protection"
    HUNG_WINDOW = "hung_window"


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: EvidenceKind
    detail: str
    value: float | None = None
    window: tuple[datetime, datetime] | None = None
    identity: ProcessIdentity | None = None
    incident_id: str | None = None
