""":class:`InstanceGuard` over a named Win32 mutex.

A named mutex in the ``Local\\`` namespace is per logon session and released by the
kernel when the owning process exits, so a crashed agent never leaves a stale lock. The
CLI probes it the same way to tell whether an agent is running. The name is derived from
the data directory: one agent per data directory, so a test or a second installation
with its own directory never collides with the installed agent.
"""

import ctypes
import hashlib
import os
import sys
from pathlib import Path
from typing import Protocol

ERROR_ALREADY_EXISTS = 183
DEFAULT_MUTEX_NAME = "Local\\WindowsMedic.Agent"


def mutex_name(data_dir: Path) -> str:
    """``Local\\WindowsMedic.Agent.<digest>`` for *data_dir*, case/separator-insensitive."""
    normalised = os.path.normcase(os.path.normpath(str(data_dir)))
    digest = hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:16]
    return f"{DEFAULT_MUTEX_NAME}.{digest}"


class _Kernel32(Protocol):
    def CreateMutexW(self, attributes: object, initial_owner: bool, name: str) -> int: ...  # noqa: N802
    def CloseHandle(self, handle: int) -> int: ...  # noqa: N802


class MutexLease:
    def __init__(self, kernel32: _Kernel32, handle: int) -> None:
        self._kernel32 = kernel32
        self._handle = handle

    def release(self) -> None:
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = 0


class NamedMutexGuard:
    def __init__(
        self, *, name: str = DEFAULT_MUTEX_NAME, kernel32: _Kernel32 | None = None
    ) -> None:
        self._name = name
        self._kernel32 = kernel32

    @property
    def name(self) -> str:
        return self._name

    def try_acquire(self) -> MutexLease | None:
        kernel32 = self._kernel32
        if kernel32 is None:
            if sys.platform != "win32":
                raise OSError("named mutexes are a Windows facility")
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ctypes.set_last_error(0)
        handle = kernel32.CreateMutexW(None, True, self._name)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(handle)
            return None
        return MutexLease(kernel32, handle)
