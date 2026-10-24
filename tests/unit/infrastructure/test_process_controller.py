"""Win32 exact-identity termination against a shape-compatible fake kernel32."""

import ctypes
from ctypes import wintypes
from datetime import UTC, datetime, timedelta

from tests.builders import BOOT, identity
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import TerminationAttempt, TerminationOutcome
from windows_medic.infrastructure.windows.nt_process_enumeration import EPOCH_AS_FILETIME
from windows_medic.infrastructure.windows.process_controller import (
    ERROR_ACCESS_DENIED,
    ERROR_INVALID_PARAMETER,
    WindowsProcessController,
    terminate_exact,
)

HANDLE = 0x1234


def ticks(moment: datetime) -> int:
    return EPOCH_AS_FILETIME + int(
        (moment - datetime(1970, 1, 1, tzinfo=UTC)).total_seconds() * 10_000_000
    )


class FakeKernel32:
    """One process behind ``pid``; every call can be scripted to fail with a Win32 error."""

    def __init__(self, pid: int, created: datetime) -> None:
        self.pid = pid
        self.created = created
        self.open_error: int | None = None
        self.times_error: int | None = None
        self.terminate_error: int | None = None
        self.terminated = False
        self.closed: list[int] = []

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:  # noqa: N802
        assert access == 0x1001
        if pid != self.pid:
            ctypes.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        if self.open_error is not None:
            ctypes.set_last_error(self.open_error)
            return 0
        return HANDLE

    def GetProcessTimes(  # noqa: N802
        self,
        handle: int,
        creation: "ctypes._Pointer[wintypes.FILETIME]",
        exit_time: "ctypes._Pointer[wintypes.FILETIME]",
        kernel: "ctypes._Pointer[wintypes.FILETIME]",
        user: "ctypes._Pointer[wintypes.FILETIME]",
    ) -> int:
        assert handle == HANDLE
        if self.times_error is not None:
            ctypes.set_last_error(self.times_error)
            return 0
        value = ticks(self.created)
        creation.contents.dwLowDateTime = value & 0xFFFFFFFF
        creation.contents.dwHighDateTime = value >> 32
        return 1

    def TerminateProcess(self, handle: int, exit_code: int) -> int:  # noqa: N802
        assert handle == HANDLE
        if self.terminate_error is not None:
            ctypes.set_last_error(self.terminate_error)
            return 0
        self.terminated = True
        return 1

    def CloseHandle(self, handle: int) -> int:  # noqa: N802
        self.closed.append(handle)
        return 1


def test_matching_identity_is_terminated_and_the_handle_closed() -> None:
    kernel32 = FakeKernel32(10, BOOT)

    attempt = terminate_exact(identity(10, BOOT), kernel32=kernel32)

    assert attempt.outcome is TerminationOutcome.SIGNALLED
    assert kernel32.terminated is True
    assert kernel32.closed == [HANDLE]


def test_a_reused_pid_is_never_terminated() -> None:
    kernel32 = FakeKernel32(10, BOOT + timedelta(seconds=1))

    attempt = terminate_exact(identity(10, BOOT), kernel32=kernel32)

    assert attempt.outcome is TerminationOutcome.IDENTITY_MISMATCH
    assert attempt.detail is not None
    assert "now belongs to a process created at" in attempt.detail
    assert kernel32.terminated is False
    assert kernel32.closed == [HANDLE]


def test_a_missing_process_is_already_gone() -> None:
    kernel32 = FakeKernel32(10, BOOT)

    attempt = terminate_exact(identity(99, BOOT), kernel32=kernel32)

    assert attempt.outcome is TerminationOutcome.ALREADY_GONE
    assert kernel32.closed == []


def test_access_denied_on_open_is_reported() -> None:
    kernel32 = FakeKernel32(10, BOOT)
    kernel32.open_error = ERROR_ACCESS_DENIED

    attempt = terminate_exact(identity(10, BOOT), kernel32=kernel32)

    assert attempt.outcome is TerminationOutcome.ACCESS_DENIED
    assert attempt.detail == "OpenProcess: access is denied"


def test_access_denied_on_terminate_is_reported() -> None:
    kernel32 = FakeKernel32(10, BOOT)
    kernel32.terminate_error = ERROR_ACCESS_DENIED

    attempt = terminate_exact(identity(10, BOOT), kernel32=kernel32)

    assert attempt.outcome is TerminationOutcome.ACCESS_DENIED
    assert attempt.detail == "TerminateProcess: access is denied"
    assert kernel32.closed == [HANDLE]


def test_other_errors_carry_the_win32_message() -> None:
    kernel32 = FakeKernel32(10, BOOT)
    kernel32.times_error = 6  # ERROR_INVALID_HANDLE

    attempt = terminate_exact(identity(10, BOOT), kernel32=kernel32)

    assert attempt.outcome is TerminationOutcome.ERROR
    assert attempt.detail is not None
    assert attempt.detail.startswith("GetProcessTimes: [WinError 6]")


def test_controller_delegates_to_the_exact_termination() -> None:
    seen: list[ProcessIdentity] = []
    attempt = TerminationAttempt(TerminationOutcome.SIGNALLED)

    def scripted(target: ProcessIdentity) -> TerminationAttempt:
        seen.append(target)
        return attempt

    controller = WindowsProcessController(terminate=scripted)

    assert controller.terminate(identity(10)) is attempt
    assert seen == [identity(10)]
