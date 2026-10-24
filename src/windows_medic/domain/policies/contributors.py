"""Deterministic, bounded ranking of resource contributors."""

from collections.abc import Callable, Iterable

from windows_medic.domain.models.metric import Metric, available
from windows_medic.domain.models.process import ProcessIdentity


def rank_top[T](
    items: Iterable[T],
    *,
    metric: Callable[[T], Metric[float]],
    identity: Callable[[T], ProcessIdentity],
    limit: int,
) -> tuple[T, ...]:
    """Return at most ``limit`` items with the highest available metric.

    Ordering is total: metric descending, then pid ascending, then create time ascending,
    so two runs over the same evidence always rank identically. Items whose metric is
    unavailable are not ranked; an unknown value is not a small value.
    """
    if limit < 0:
        raise ValueError(f"limit cannot be negative, got {limit}")

    scored: list[tuple[float, ProcessIdentity, T]] = []
    for item in items:
        value = metric(item)
        if available(value):
            scored.append((value, identity(item), item))
    scored.sort(key=lambda entry: (-entry[0], entry[1]))
    return tuple(item for _, _, item in scored[:limit])
