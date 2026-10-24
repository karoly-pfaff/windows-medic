"""Narrow Win32 call for the system commit charge.

``GetPerformanceInfo`` reports commit total/limit in pages; that is the figure Task
Manager shows as "Committed". psutil's ``swap_memory`` is not a reliable substitute.
"""

import ctypes
import sys
from collections.abc import Callable
from ctypes import wintypes
from typing import Protocol

from windows_medic.domain.models.metric import Metric, Unavailable, UnavailableReason
from windows_medic.domain.models.samples import CommitObservation

type CommitPages = tuple[int, int, int]
"""``(commit_total_pages, commit_limit_pages, page_size_bytes)``."""


class PerformanceInformation(ctypes.Structure):
    """``PERFORMANCE_INFORMATION`` as filled by ``GetPerformanceInfo``."""

    _fields_ = (
        ("cb", wintypes.DWORD),
        ("CommitTotal", ctypes.c_size_t),
        ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t),
        ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t),
        ("KernelPaged", ctypes.c_size_t),
        ("KernelNonpaged", ctypes.c_size_t),
        ("PageSize", ctypes.c_size_t),
        ("HandleCount", wintypes.DWORD),
        ("ProcessCount", wintypes.DWORD),
        ("ThreadCount", wintypes.DWORD),
    )


class _Psapi(Protocol):
    def GetPerformanceInfo(  # noqa: N802 - Win32 export name
        self, info: "ctypes._Pointer[PerformanceInformation]", size: int
    ) -> int: ...


def query_performance_information(*, psapi: _Psapi | None = None) -> CommitPages:
    """Call ``GetPerformanceInfo``. Raises ``NotImplementedError`` off Windows."""
    if psapi is None:
        if sys.platform != "win32":
            raise NotImplementedError("GetPerformanceInfo is a Windows API")
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
    info = PerformanceInformation()
    info.cb = ctypes.sizeof(info)
    if not psapi.GetPerformanceInfo(ctypes.pointer(info), info.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return int(info.CommitTotal), int(info.CommitLimit), int(info.PageSize)


def read_commit(
    *, query: Callable[[], CommitPages] = query_performance_information
) -> Metric[CommitObservation]:
    """Current commit charge, or an explicit reason it is unavailable."""
    try:
        total_pages, limit_pages, page_size = query()
    except NotImplementedError:
        return Unavailable(UnavailableReason.NOT_SUPPORTED)
    except OSError:
        return Unavailable(UnavailableReason.ERROR)
    try:
        return CommitObservation(
            limit_bytes=limit_pages * page_size, used_bytes=total_pages * page_size
        )
    except ValueError:
        return Unavailable(UnavailableReason.INCONSISTENT)
