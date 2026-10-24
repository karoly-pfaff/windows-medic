""":class:`ElevatedHelper` for Windows: launch the helper through UAC and read its result.

The helper is started with ``ShellExecuteExW`` and the ``runas`` verb (the UAC prompt),
with an argument array encoded by :mod:`elevation_protocol` — nothing else can be passed.
The launcher waits a bounded time for the helper to exit and then reads the result file
it asked for. A cancelled prompt is *declined*; a helper that does not finish in time is
*timed out*; a missing or unreadable result is a *failure*. All are typed results, never
exceptions.
"""

import ctypes
import subprocess
import sys
import uuid
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from windows_medic.application.operations import ELEVATED_RESULT_PREFIX
from windows_medic.domain.models.elevation import (
    ElevatedOutcome,
    ElevatedRequest,
    ElevatedResult,
)
from windows_medic.infrastructure.windows.elevation_protocol import (
    RESULT_SUFFIX,
    decode_result,
    encode_request,
)

ERROR_CANCELLED = 1223
SEE_MASK_NOCLOSEPROCESS = 0x0000_0040
SEE_MASK_NOASYNC = 0x0000_0100
SEE_MASK_FLAG_NO_UI = 0x0000_0400
SW_HIDE = 0
WAIT_OBJECT_0 = 0x0000_0000
WAIT_TIMEOUT = 0x0000_0102
INFINITE = 0xFFFF_FFFF


class LaunchOutcome(StrEnum):
    EXITED = "exited"
    DECLINED = "declined"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Launch:
    outcome: LaunchOutcome
    exit_code: int | None = None
    detail: str | None = None


type Launcher = Callable[[Path, list[str], timedelta], Launch]


class ShellExecuteInfoW(ctypes.Structure):
    _fields_ = (
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    )


class _Shell32(Protocol):
    def ShellExecuteExW(self, info: "ctypes._Pointer[ShellExecuteInfoW]") -> int: ...  # noqa: N802


class _Kernel32(Protocol):
    def WaitForSingleObject(self, handle: int, milliseconds: int) -> int: ...  # noqa: N802
    def GetExitCodeProcess(  # noqa: N802
        self, handle: int, code: "ctypes._Pointer[wintypes.DWORD]"
    ) -> int: ...
    def CloseHandle(self, handle: int) -> int: ...  # noqa: N802


def launch_as_administrator(
    executable: Path,
    parameters: list[str],
    timeout: timedelta,
    *,
    shell32: _Shell32 | None = None,
    kernel32: _Kernel32 | None = None,
) -> Launch:
    """Run *executable* with *parameters* through the UAC prompt and wait for it to exit."""
    if shell32 is None or kernel32 is None:
        if sys.platform != "win32":
            return Launch(LaunchOutcome.FAILED, detail="ShellExecuteEx is a Windows API")
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    info = ShellExecuteInfoW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI
    info.lpVerb = "runas"
    info.lpFile = str(executable)
    info.lpParameters = subprocess.list2cmdline(parameters)
    info.nShow = SW_HIDE
    ctypes.set_last_error(0)
    if not shell32.ShellExecuteExW(ctypes.pointer(info)):
        error = ctypes.get_last_error()
        if error == ERROR_CANCELLED:
            return Launch(LaunchOutcome.DECLINED, detail="the UAC prompt was cancelled")
        return Launch(LaunchOutcome.FAILED, detail=f"ShellExecuteEx: {ctypes.WinError(error)}")
    handle = int(info.hProcess or 0)
    if not handle:
        return Launch(LaunchOutcome.FAILED, detail="ShellExecuteEx returned no process handle")
    try:
        return _wait_for_exit(kernel32, handle, timeout)
    finally:
        kernel32.CloseHandle(handle)


def _wait_for_exit(kernel32: _Kernel32, handle: int, timeout: timedelta) -> Launch:
    waited = kernel32.WaitForSingleObject(handle, int(timeout.total_seconds() * 1000))
    if waited == WAIT_TIMEOUT:
        return Launch(LaunchOutcome.TIMED_OUT, detail="the helper did not finish in time")
    if waited != WAIT_OBJECT_0:
        return Launch(LaunchOutcome.FAILED, detail=f"WaitForSingleObject returned {waited}")
    code = wintypes.DWORD(0)
    if not kernel32.GetExitCodeProcess(handle, ctypes.pointer(code)):
        return Launch(LaunchOutcome.FAILED, detail="GetExitCodeProcess failed")
    return Launch(LaunchOutcome.EXITED, exit_code=int(code.value))


class UacElevationLauncher:
    """``ElevatedHelper`` that runs the one-shot helper executable as administrator."""

    def __init__(
        self,
        *,
        helper: Path,
        result_dir: Path,
        timeout: timedelta,
        launch: Launcher = launch_as_administrator,
    ) -> None:
        self._helper = helper
        self._result_dir = result_dir
        self._timeout = timeout
        self._launch = launch

    def run(self, request: ElevatedRequest) -> ElevatedResult:
        result_path = (
            self._result_dir / f"{ELEVATED_RESULT_PREFIX}{uuid.uuid4().hex}{RESULT_SUFFIX}"
        )
        try:
            self._result_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return ElevatedResult(
                ElevatedOutcome.FAILED, detail=f"cannot prepare result dir: {exc}"
            )
        try:
            launch = self._launch(self._helper, encode_request(request, result_path), self._timeout)
            if launch.outcome is LaunchOutcome.DECLINED:
                return ElevatedResult(ElevatedOutcome.DECLINED, detail=launch.detail)
            if launch.outcome is LaunchOutcome.TIMED_OUT:
                return ElevatedResult(ElevatedOutcome.TIMED_OUT, detail=launch.detail)
            if launch.outcome is LaunchOutcome.FAILED:
                return ElevatedResult(ElevatedOutcome.FAILED, detail=launch.detail)
            return self._read(result_path, launch)
        finally:
            _remove_quietly(result_path)

    def _read(self, result_path: Path, launch: Launch) -> ElevatedResult:
        try:
            text = result_path.read_text(encoding="utf-8")
        except OSError:
            return ElevatedResult(
                ElevatedOutcome.FAILED,
                detail=f"the helper exited with code {launch.exit_code} and left no result",
            )
        result = decode_result(text)
        if result is None:
            return ElevatedResult(
                ElevatedOutcome.FAILED, detail="the helper left an unreadable result"
            )
        return result


def _remove_quietly(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        return
