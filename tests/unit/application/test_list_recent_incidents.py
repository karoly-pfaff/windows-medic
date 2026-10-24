"""ListRecentIncidents: bounded summaries, newest first."""

from datetime import timedelta

import pytest

from tests.builders import T0
from tests.fakes import FakeIncidentRepository
from windows_medic.application.use_cases.list_recent_incidents import (
    IncidentListLimits,
    ListRecentIncidents,
)
from windows_medic.domain.models.incident import (
    EvidenceLimits,
    Incident,
    IncidentKind,
    IncidentStatus,
    open_incident,
)

LIMITS = EvidenceLimits(
    max_system_samples=10, max_contributors=5, high_severity_after=timedelta(seconds=120)
)


def incident(number: int) -> Incident:
    started = T0 + timedelta(minutes=number)
    return open_incident(
        incident_id=f"inc-{number}",
        kind=IncidentKind.CPU_PRESSURE,
        started_at=started,
        triggered_at=started + timedelta(seconds=20),
        threshold=90.0,
        pre_trigger=(),
        contributors=(),
        evidence_window=(started - timedelta(minutes=1), started),
        limits=LIMITS,
    )


def test_returns_summaries_newest_first_bounded_by_the_requested_limit() -> None:
    repository = FakeIncidentRepository()
    for number in range(5):
        repository.save(incident(number))
    use_case = ListRecentIncidents(repository, IncidentListLimits(max_limit=50))

    summaries = use_case.execute(limit=3)

    assert [s.id for s in summaries] == ["inc-4", "inc-3", "inc-2"]
    assert summaries[0].kind is IncidentKind.CPU_PRESSURE
    assert summaries[0].status is IncidentStatus.OPEN
    assert summaries[0].started_at == T0 + timedelta(minutes=4)
    assert summaries[0].closed_at is None
    assert summaries[0].peak == 90.0


def test_limit_is_capped_by_the_configured_maximum() -> None:
    repository = FakeIncidentRepository()
    for number in range(10):
        repository.save(incident(number))
    use_case = ListRecentIncidents(repository, IncidentListLimits(max_limit=4))

    assert len(use_case.execute(limit=100)) == 4
    assert repository.recent_calls == [4]


def test_limit_must_be_positive() -> None:
    use_case = ListRecentIncidents(FakeIncidentRepository(), IncidentListLimits(max_limit=4))

    with pytest.raises(ValueError, match="limit"):
        use_case.execute(limit=0)


def test_default_limit_is_the_documented_ten() -> None:
    repository = FakeIncidentRepository()
    for number in range(12):
        repository.save(incident(number))

    assert len(ListRecentIncidents(repository, IncidentListLimits(max_limit=50)).execute()) == 10


def test_configured_maximum_must_be_positive() -> None:
    with pytest.raises(ValueError, match="max_limit"):
        IncidentListLimits(max_limit=0)
