"""Contributor ranking across the incident window and the current sample."""

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.builders import BOOT, GIB, T0, contributor, identity, incident
from windows_medic.domain.models.incident import IncidentKind
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.policies.contributor_ranking import rank_contributors

TOTAL = 32 * GIB
UNKNOWN = Unavailable(UnavailableReason.ACCESS_DENIED)


def test_incident_window_evidence_outranks_the_latest_sample_alone() -> None:
    # A hogged CPU during an incident and is gone now; B is busy right now only;
    # C was a modest contributor in two incidents and still is.
    incidents = (
        incident(
            "new",
            started_at=T0 - timedelta(minutes=5),
            contributors=(contributor(1, cpu_percent=60.0), contributor(3, cpu_percent=20.0)),
        ),
        incident(
            "old",
            started_at=T0 - timedelta(minutes=20),
            contributors=(contributor(3, cpu_percent=18.0),),
        ),
    )
    current = (contributor(2, cpu_percent=40.0), contributor(3, cpu_percent=20.0))

    ranked = rank_contributors(
        incidents, current, memory_total_bytes=TOTAL, limit=10, max_incidents_per_contributor=5
    )

    assert [c.identity.pid for c in ranked] == [1, 2, 3]
    assert ranked[0].cpu_share == 60.0
    assert ranked[0].present_now is False
    assert ranked[0].current is None
    assert ranked[1].present_now is True
    assert [ic.incident_id for ic in ranked[2].incident_contributions] == ["new", "old"]
    assert ranked[2].incident_contributions[0].kind is IncidentKind.CPU_PRESSURE
    assert ranked[2].incident_contributions[1].cpu_percent == 18.0


def test_equal_shares_rank_by_incident_count_then_identity() -> None:
    incidents = (incident("i", contributors=(contributor(7, cpu_percent=25.0),)),)
    current = (contributor(5, cpu_percent=25.0), contributor(6, cpu_percent=25.0))

    ranked = rank_contributors(
        incidents, current, memory_total_bytes=TOTAL, limit=10, max_incidents_per_contributor=5
    )

    assert [c.identity.pid for c in ranked] == [7, 5, 6]


def test_memory_share_is_a_share_of_physical_memory_and_can_dominate() -> None:
    current = (
        contributor(1, cpu_percent=20.0, working_set_bytes=1 * GIB),
        contributor(2, cpu_percent=2.0, working_set_bytes=8 * GIB),
    )

    ranked = rank_contributors(
        (), current, memory_total_bytes=TOTAL, limit=10, max_incidents_per_contributor=5
    )

    assert [c.identity.pid for c in ranked] == [2, 1]
    assert ranked[0].memory_share == 25.0
    assert ranked[0].dominant_share == 25.0
    assert ranked[1].dominant_share == 20.0


def test_unavailable_metrics_are_not_zero_and_unmeasurable_processes_are_left_out() -> None:
    incidents = (
        incident(
            "i",
            contributors=(
                contributor(1, cpu_percent=UNKNOWN, working_set_bytes=UNKNOWN),
                contributor(2, cpu_percent=UNKNOWN, working_set_bytes=4 * GIB),
            ),
        ),
    )
    current = (contributor(2, cpu_percent=Unavailable(UnavailableReason.NO_BASELINE)),)

    ranked = rank_contributors(
        incidents, current, memory_total_bytes=TOTAL, limit=10, max_incidents_per_contributor=5
    )

    assert [c.identity.pid for c in ranked] == [2]
    assert ranked[0].cpu_share == 0.0
    assert ranked[0].memory_share == 12.5


def test_results_are_bounded_and_incident_history_is_newest_first() -> None:
    incidents = tuple(
        incident(
            f"i{n}",
            started_at=T0 - timedelta(minutes=30 - n),
            contributors=(contributor(1, cpu_percent=50.0),),
        )
        for n in range(6)
    )
    current = tuple(contributor(pid, cpu_percent=float(pid)) for pid in range(2, 10))

    ranked = rank_contributors(
        incidents, current, memory_total_bytes=TOTAL, limit=3, max_incidents_per_contributor=2
    )

    assert [c.identity.pid for c in ranked] == [1, 9, 8]
    assert [ic.incident_id for ic in ranked[0].incident_contributions] == ["i5", "i4"]


def test_a_reused_pid_is_a_different_contributor() -> None:
    older = contributor(1, cpu_percent=50.0)
    newer = contributor(1, created=BOOT + timedelta(hours=1), cpu_percent=10.0)
    incidents = (incident("i", contributors=(older,)),)

    ranked = rank_contributors(
        incidents, (newer,), memory_total_bytes=TOTAL, limit=10, max_incidents_per_contributor=5
    )

    assert [c.identity for c in ranked] == [identity(1), identity(1, BOOT + timedelta(hours=1))]
    assert ranked[0].present_now is False
    assert ranked[1].incident_contributions == ()


def test_memory_total_must_be_positive() -> None:
    with pytest.raises(ValueError, match="memory_total_bytes"):
        rank_contributors((), (), memory_total_bytes=0, limit=1, max_incidents_per_contributor=1)


def test_a_present_process_with_only_cpu_known_has_no_memory_share() -> None:
    current = (contributor(1, cpu_percent=20.0, working_set_bytes=UNKNOWN),)

    (ranked,) = rank_contributors(
        (), current, memory_total_bytes=TOTAL, limit=10, max_incidents_per_contributor=5
    )

    assert ranked.cpu_share == 20.0
    assert ranked.memory_share == 0.0


@given(
    shares=st.lists(
        st.tuples(st.integers(min_value=1, max_value=6), st.floats(min_value=0, max_value=100)),
        max_size=12,
    ),
    limit=st.integers(min_value=1, max_value=6),
)
def test_ranking_is_total_and_independent_of_input_order(
    shares: list[tuple[int, float]], limit: int
) -> None:
    """Same evidence in any order -> same ranking; the result is bounded by ``limit``."""
    current = tuple(contributor(pid, cpu_percent=cpu) for pid, cpu in dict(shares).items())
    incidents = (incident("i", contributors=current[::2]),)

    forward = rank_contributors(
        incidents, current, memory_total_bytes=TOTAL, limit=limit, max_incidents_per_contributor=3
    )
    backward = rank_contributors(
        incidents,
        current[::-1],
        memory_total_bytes=TOTAL,
        limit=limit,
        max_incidents_per_contributor=3,
    )

    assert forward == backward
    assert len(forward) <= limit
    assert [c.dominant_share for c in forward] == sorted(
        (c.dominant_share for c in forward), reverse=True
    )
