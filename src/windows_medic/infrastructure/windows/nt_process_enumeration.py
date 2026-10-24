"""One-call process inventory through ``NtQuerySystemInformation`` (docs/architecture.md §13).

``SystemProcessInformation`` returns a chain of variable-length entries, one per process,
observed atomically. This module owns the ABI layout and turns it into plain typed entries;
it has no knowledge of the domain model.
"""

import ctypes
import sys
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

SYSTEM_PROCESS_INFORMATION_CLASS = 5
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
INITIAL_BUFFER_BYTES = 1024 * 1024
MAX_QUERY_ATTEMPTS = 8
IDLE_PROCESS_PID = 0

EPOCH_AS_FILETIME = 116_444_736_000_000_000
"""1970-01-01T00:00:00Z expressed in 100 ns ticks since 1601-01-01 (Windows FILETIME)."""
_FILETIME_TICKS_PER_SECOND = 10_000_000
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class UnicodeString(ctypes.Structure):
    _fields_ = (
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    )


class SystemProcessInformation(ctypes.Structure):
    """Fixed-size head of ``SYSTEM_PROCESS_INFORMATION`` (thread entries follow it)."""

    _fields_ = (
        ("NextEntryOffset", wintypes.ULONG),
        ("NumberOfThreads", wintypes.ULONG),
        ("WorkingSetPrivateSize", ctypes.c_longlong),
        ("HardFaultCount", wintypes.ULONG),
        ("NumberOfThreadsHighWatermark", wintypes.ULONG),
        ("CycleTime", ctypes.c_ulonglong),
        ("CreateTime", ctypes.c_longlong),
        ("UserTime", ctypes.c_longlong),
        ("KernelTime", ctypes.c_longlong),
        ("ImageName", UnicodeString),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_size_t),
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),
        ("HandleCount", wintypes.ULONG),
        ("SessionId", wintypes.ULONG),
        ("UniqueProcessKey", ctypes.c_size_t),
        ("PeakVirtualSize", ctypes.c_size_t),
        ("VirtualSize", ctypes.c_size_t),
        ("PageFaultCount", wintypes.ULONG),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivatePageCount", ctypes.c_size_t),
        ("ReadOperationCount", ctypes.c_longlong),
        ("WriteOperationCount", ctypes.c_longlong),
        ("OtherOperationCount", ctypes.c_longlong),
        ("ReadTransferCount", ctypes.c_longlong),
        ("WriteTransferCount", ctypes.c_longlong),
        ("OtherTransferCount", ctypes.c_longlong),
    )


type ProcessInformationBuffer = ctypes.Array[ctypes.c_char]


class _NtDll(Protocol):
    def NtQuerySystemInformation(  # noqa: N802 - Win32 export name
        self,
        information_class: int,
        buffer: ProcessInformationBuffer,
        size: int,
        needed: "ctypes._Pointer[wintypes.ULONG]",
    ) -> int: ...


@dataclass(frozen=True, slots=True)
class NtProcessEntry:
    """One process as reported by the kernel. Counters are cumulative."""

    pid: int
    parent_pid: int
    create_time: datetime
    cpu_time_seconds: float
    thread_count: int
    handle_count: int
    working_set_bytes: int
    private_bytes: int
    io_read_bytes: int
    io_write_bytes: int
    session_id: int
    image_name: str


def filetime_to_datetime(ticks: int) -> datetime:
    """Convert 100 ns ticks since 1601 to an aware UTC datetime (microsecond precision)."""
    return _EPOCH + timedelta(microseconds=(ticks - EPOCH_AS_FILETIME) // 10)


def query_system_process_information(*, ntdll: _NtDll | None = None) -> ProcessInformationBuffer:
    """Call ``NtQuerySystemInformation``; grows the buffer until the kernel is satisfied."""
    if ntdll is None:
        if sys.platform != "win32":
            raise NotImplementedError("NtQuerySystemInformation is a Windows API")
        ntdll = ctypes.WinDLL("ntdll")
    size = INITIAL_BUFFER_BYTES
    for _ in range(MAX_QUERY_ATTEMPTS):
        buffer = ctypes.create_string_buffer(size)
        needed = wintypes.ULONG(0)
        status = ntdll.NtQuerySystemInformation(
            SYSTEM_PROCESS_INFORMATION_CLASS, buffer, size, ctypes.pointer(needed)
        )
        if status == 0:
            return buffer
        if status & 0xFFFFFFFF != STATUS_INFO_LENGTH_MISMATCH:
            raise OSError(
                f"NtQuerySystemInformation failed with NTSTATUS 0x{status & 0xFFFFFFFF:08X}"
            )
        size = max(size * 2, needed.value + size // 4)
    raise OSError("NtQuerySystemInformation buffer kept growing; process table too volatile")


def parse_process_information(buffer: ProcessInformationBuffer) -> list[NtProcessEntry]:
    """Walk the entry chain. Stops at offset 0 or when an offset leaves the buffer."""
    entries: list[NtProcessEntry] = []
    entry_size = ctypes.sizeof(SystemProcessInformation)
    total = ctypes.sizeof(buffer)
    offset = 0
    while offset + entry_size <= total:
        raw = SystemProcessInformation.from_buffer_copy(buffer, offset)
        if raw.UniqueProcessId != IDLE_PROCESS_PID:
            entries.append(_entry(raw))
        if raw.NextEntryOffset == 0:
            break
        offset += raw.NextEntryOffset
    return entries


def enumerate_processes(
    *, query: Callable[[], ProcessInformationBuffer] = query_system_process_information
) -> list[NtProcessEntry]:
    """Every process on the system right now, excluding the idle pseudo-process."""
    return parse_process_information(query())


def _entry(raw: SystemProcessInformation) -> NtProcessEntry:
    return NtProcessEntry(
        pid=int(raw.UniqueProcessId),
        parent_pid=int(raw.InheritedFromUniqueProcessId),
        create_time=filetime_to_datetime(int(raw.CreateTime)),
        cpu_time_seconds=(int(raw.UserTime) + int(raw.KernelTime)) / _FILETIME_TICKS_PER_SECOND,
        thread_count=int(raw.NumberOfThreads),
        handle_count=int(raw.HandleCount),
        working_set_bytes=int(raw.WorkingSetSize),
        private_bytes=int(raw.PrivatePageCount),
        io_read_bytes=int(raw.ReadTransferCount),
        io_write_bytes=int(raw.WriteTransferCount),
        session_id=int(raw.SessionId),
        image_name=_image_name(raw.ImageName),
    )


def _image_name(name: UnicodeString) -> str:
    if not name.Buffer or name.Length == 0:
        return ""
    return ctypes.wstring_at(name.Buffer, name.Length // 2)
