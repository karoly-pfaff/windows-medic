"""Hung top-level windows via Win32 ``IsHungAppWindow``.

``IsHungAppWindow`` is Windows' own not-responding verdict (the one behind the "(Not
Responding)" title suffix): the window's thread has not processed messages for more than
five seconds. Only visible top-level windows are considered; every GUI process owns many
hidden helper windows and the user-visible symptom is what matters as evidence. Owners are
reported as PIDs, as Windows reports them; identity resolution is the application's job.
"""

import ctypes
import logging
import sys
from collections.abc import Callable
from ctypes import wintypes
from typing import Protocol

from windows_medic.application.observability import log_event
from windows_medic.domain.models.gui import HungWindow

_logger = logging.getLogger(__name__)

DEFAULT_LIMIT = 32
DEFAULT_MAX_TITLE = 80

_ENUM_WINDOWS_PROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


class _User32(Protocol):
    """The user32 exports used here, as ctypes exposes them."""

    def EnumWindows(  # noqa: N802 - Win32 export name
        self, callback: Callable[[int, int], int], lparam: int
    ) -> int: ...
    def IsWindowVisible(self, hwnd: int) -> int: ...  # noqa: N802
    def IsHungAppWindow(self, hwnd: int) -> int: ...  # noqa: N802
    def GetWindowThreadProcessId(  # noqa: N802
        self, hwnd: int, pid: "ctypes._Pointer[wintypes.DWORD]"
    ) -> int: ...
    def GetWindowTextW(  # noqa: N802
        self, hwnd: int, buffer: ctypes.Array[ctypes.c_wchar], count: int
    ) -> int: ...


def enumerate_hung_windows(
    *, user32: _User32 | None = None, limit: int, max_title: int
) -> tuple[HungWindow, ...]:
    """Visible top-level windows Windows considers hung, at most *limit*.

    Raises ``NotImplementedError`` off Windows and ``OSError`` when enumeration fails.
    """
    if user32 is None:
        if sys.platform != "win32":
            raise NotImplementedError("EnumWindows is a Windows API")
        user32 = ctypes.WinDLL("user32", use_last_error=True)
    api = user32
    found: list[HungWindow] = []

    def visit(hwnd: int, _lparam: int) -> int:
        if not api.IsWindowVisible(hwnd) or not api.IsHungAppWindow(hwnd):
            return 1
        pid = wintypes.DWORD(0)
        api.GetWindowThreadProcessId(hwnd, ctypes.pointer(pid))
        if pid.value == 0:
            return 1
        buffer = ctypes.create_unicode_buffer(max_title + 1)
        api.GetWindowTextW(hwnd, buffer, max_title + 1)
        found.append(HungWindow(owner_pid=int(pid.value), title=buffer.value[:max_title]))
        return 1 if len(found) < limit else 0

    callback = _ENUM_WINDOWS_PROC(visit)
    ctypes.set_last_error(0)
    if not api.EnumWindows(callback, 0) and len(found) < limit:
        error = ctypes.get_last_error()
        if error:
            raise ctypes.WinError(error)
    return tuple(found)


class Win32HungWindowReader:
    """``HungWindowReader`` over :func:`enumerate_hung_windows`, contained on failure."""

    def __init__(
        self,
        *,
        limit: int = DEFAULT_LIMIT,
        max_title: int = DEFAULT_MAX_TITLE,
        enumerate_windows: Callable[..., tuple[HungWindow, ...]] = enumerate_hung_windows,
    ) -> None:
        self._limit = limit
        self._max_title = max_title
        self._enumerate = enumerate_windows

    def hung_windows(self) -> tuple[HungWindow, ...]:
        """Hung windows, or nothing (logged) when Windows cannot be asked."""
        try:
            return self._enumerate(limit=self._limit, max_title=self._max_title)
        except (NotImplementedError, OSError) as exc:
            log_event(_logger, "hung_windows.unavailable", level=logging.WARNING, error=str(exc))
            return ()
