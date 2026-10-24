""":class:`ProcessController` for Windows: terminate by exact identity through Win32.

The PID is opened, the creation time behind the handle is read (``GetProcessTimes``, the
same kernel figure the inventory reports) and compared with the requested identity, and
only then is ``TerminateProcess`` called on that very handle. A PID that has been reused
therefore never receives the call. No shell, no psutil name matching, no elevation.
"""

import ctypes
import sys
from collections.abc import Callable
from ctypes import wintypes
from typing import Protocol

from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import TerminationAttempt, TerminationOutcome
from windows_medic.infrastructure.windows.nt_process_enumeration import filetime_to_datetime

PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
EXIT_CODE = 1


class _Kernel32(Protocol):
    """The kernel32 exports used here, as ctypes exposes them."""

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int: ...  # noqa: N802
    def GetProcessTimes(  # noqa: N802
        self,
        handle: int,
        creation: "ctypes._Pointer[wintypes.FILETIME]",
        exit_time: "ctypes._Pointer[wintypes.FILETIME]",
        kernel: "ctypes._Pointer[wintypes.FILETIME]",
        user: "ctypes._Pointer[wintypes.FILETIME]",
    ) -> int: ...
    def TerminateProcess(self, handle: int, exit_code: int) -> int: ...  # noqa: N802
    def CloseHandle(self, handle: int) -> int: ...  # noqa: N802


def terminate_exact(
    identity: ProcessIdentity, *, kernel32: _Kernel32 | None = None
) -> TerminationAttempt:
    """Terminate *identity* only if the PID still carries its create time."""
    if kernel32 is None:
        if sys.platform != "win32":
            return TerminationAttempt(TerminationOutcome.ERROR, "TerminateProcess is a Windows API")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ctypes.set_last_error(0)
    handle = kernel32.OpenProcess(
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, False, identity.pid
    )
    if not handle:
        return _failure(ctypes.get_last_error(), "OpenProcess")
    try:
        creation, exit_time, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.pointer(creation),
            ctypes.pointer(exit_time),
            ctypes.pointer(kernel),
            ctypes.pointer(user),
        ):
            return _failure(ctypes.get_last_error(), "GetProcessTimes")
        ticks = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
        if filetime_to_datetime(ticks) != identity.create_time:
            return TerminationAttempt(
                TerminationOutcome.IDENTITY_MISMATCH,
                f"pid {identity.pid} now belongs to a process created at "
                f"{filetime_to_datetime(ticks).isoformat()}",
            )
        if not kernel32.TerminateProcess(handle, EXIT_CODE):
            return _failure(ctypes.get_last_error(), "TerminateProcess")
        return TerminationAttempt(TerminationOutcome.SIGNALLED)
    finally:
        kernel32.CloseHandle(handle)


def _failure(error: int, call: str) -> TerminationAttempt:
    if error == ERROR_ACCESS_DENIED:
        return TerminationAttempt(TerminationOutcome.ACCESS_DENIED, f"{call}: access is denied")
    if error == ERROR_INVALID_PARAMETER and call == "OpenProcess":
        return TerminationAttempt(TerminationOutcome.ALREADY_GONE, "no such process")
    return TerminationAttempt(TerminationOutcome.ERROR, f"{call}: {ctypes.WinError(error)}")


class WindowsProcessController:
    """``ProcessController`` over :func:`terminate_exact`."""

    def __init__(
        self,
        *,
        terminate: Callable[[ProcessIdentity], TerminationAttempt] = terminate_exact,
    ) -> None:
        self._terminate = terminate

    def terminate(self, identity: ProcessIdentity) -> TerminationAttempt:
        return self._terminate(identity)
