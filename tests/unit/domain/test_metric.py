"""Metric[T]: an observed value or an explicit, typed reason it is unavailable."""

from windows_medic.domain.models.metric import (
    Metric,
    Unavailable,
    UnavailableReason,
    available,
)


def test_available_narrows_present_values() -> None:
    metric: Metric[int] = 7

    assert available(metric)
    assert metric + 1 == 8


def test_unavailable_carries_its_reason() -> None:
    metric: Metric[int] = Unavailable(UnavailableReason.ACCESS_DENIED)

    assert not available(metric)
    assert isinstance(metric, Unavailable)
    assert metric.reason is UnavailableReason.ACCESS_DENIED


def test_unavailable_values_with_the_same_reason_are_equal() -> None:
    gone = UnavailableReason.PROCESS_GONE

    assert Unavailable(gone) == Unavailable(gone)
    assert Unavailable(UnavailableReason.PROCESS_GONE) != Unavailable(UnavailableReason.ERROR)


def test_reasons_are_a_closed_vocabulary() -> None:
    assert {reason.value for reason in UnavailableReason} == {
        "access_denied",
        "process_gone",
        "not_supported",
        "error",
        "no_baseline",
        "inconsistent",
    }
