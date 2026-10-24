"""Cheap answers for processes the caller may not open.

psutil learns that a process denies access only after a failing ``OpenProcess`` followed
by a full PID enumeration, per field, which costs tens of milliseconds each; with a few
hundred protected processes a cold snapshot took seconds. This module asks the two
questions that matter directly:

- may this process be opened with ``PROCESS_QUERY_LIMITED_INFORMATION`` (what reading its
  command line and owner needs)?
- what is its executable path, without a handle (``SystemProcessIdInformation``, the same
  source psutil falls back to)?

Read-only: nothing here can change a process.
"""

import ctypes
import string
import sys
from ctypes import wintypes

from windows_medic.infrastructure.windows.nt_process_enumeration import UnicodeString

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ACCESS_DENIED = 5
SYSTEM_PROCESS_ID_INFORMATION_CLASS = 88
STATUS_INVALID_CID = 0xC000000B
# Long enough for any NT image path (32767 UTF-16 code units plus a terminator).
_IMAGE_PATH_BYTES = 0xFFFE
_DOS_DEVICE_CHARS = 1024


class SystemProcessIdInformation(ctypes.Structure):
    _fields_ = (
        ("ProcessId", ctypes.c_void_p),
        ("ImageName", UnicodeString),
    )


class ProcessGoneError(OSError):
    """The process exited before its image path could be read."""


def _kernel32() -> ctypes.WinDLL:
    if sys.platform != "win32":
        raise NotImplementedError("process access checks are Windows APIs")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.QueryDosDeviceW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    kernel32.QueryDosDeviceW.restype = wintypes.DWORD
    return kernel32


def may_open_limited(pid: int) -> bool:
    """False only when Windows denies even limited query access to *pid*.

    Any other failure (the process is gone, an invalid PID) answers True so the caller
    takes its normal path and reports that outcome itself.
    """
    kernel32 = _kernel32()
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        kernel32.CloseHandle(handle)
        return True
    return ctypes.get_last_error() != ERROR_ACCESS_DENIED


def image_path_without_handle(pid: int) -> str:
    """The executable path of *pid* as a DOS path (``C:\\...``); ``""`` when it has none.

    Raises:
        ProcessGoneError: When *pid* no longer exists.
        OSError: When the kernel refuses the query for another reason.
    """
    nt_path = _nt_image_path(pid)
    return dos_path(nt_path, _dos_devices())


def dos_path(nt_path: str, devices: dict[str, str]) -> str:
    """Rewrite ``\\Device\\HarddiskVolumeN\\...`` through the drive-letter map *devices*
    (device -> ``C:``); a path on no mapped device is returned unchanged."""
    lowered = nt_path.lower()
    for device, drive in devices.items():
        prefix = device.lower() + "\\"
        if lowered.startswith(prefix):
            return drive + nt_path[len(device) :]
    return nt_path


def _nt_image_path(pid: int) -> str:
    ntdll = ctypes.WinDLL("ntdll")
    buffer = ctypes.create_unicode_buffer(_IMAGE_PATH_BYTES // 2)
    info = SystemProcessIdInformation()
    info.ProcessId = pid
    info.ImageName.Length = 0
    info.ImageName.MaximumLength = _IMAGE_PATH_BYTES
    info.ImageName.Buffer = ctypes.cast(buffer, ctypes.c_void_p).value
    status = ntdll.NtQuerySystemInformation(
        SYSTEM_PROCESS_ID_INFORMATION_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
        None,
    )
    status &= 0xFFFFFFFF
    if status == STATUS_INVALID_CID:
        raise ProcessGoneError(f"pid {pid} no longer exists")
    if status != 0:
        raise OSError(f"SystemProcessIdInformation failed with NTSTATUS 0x{status:08X}")
    return ctypes.wstring_at(buffer, info.ImageName.Length // 2)


def _dos_devices() -> dict[str, str]:
    """``\\Device\\HarddiskVolumeN`` -> ``C:`` for every drive letter that has a target."""
    kernel32 = _kernel32()
    devices: dict[str, str] = {}
    target = ctypes.create_unicode_buffer(_DOS_DEVICE_CHARS)
    for letter in string.ascii_uppercase:
        drive = f"{letter}:"
        if kernel32.QueryDosDeviceW(drive, target, _DOS_DEVICE_CHARS):
            devices[target.value] = drive
    return devices
