"""Explicit representation of observed values that could not be obtained.

Windows may deny a field, a process may exit mid-read, or a rate may have no baseline yet.
Such facts are evidence and must never be replaced by a fake default such as ``0``.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeIs


class UnavailableReason(StrEnum):
    """Why a value is missing. Closed vocabulary; add a member rather than free text."""

    ACCESS_DENIED = "access_denied"
    PROCESS_GONE = "process_gone"
    NOT_SUPPORTED = "not_supported"
    ERROR = "error"
    NO_BASELINE = "no_baseline"
    INCONSISTENT = "inconsistent"


@dataclass(frozen=True, slots=True)
class Unavailable:
    """Marker carried in place of a value that could not be observed."""

    reason: UnavailableReason


type Metric[T] = T | Unavailable


def available[T](metric: Metric[T]) -> TypeIs[T]:
    """Narrow a metric to its value type when it was observed."""
    return not isinstance(metric, Unavailable)
