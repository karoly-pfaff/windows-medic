"""Parsing of SYSTEM_PROCESS_INFORMATION chains into typed entries.

Synthetic buffers are built with the adapter's own ctypes layout so the unit tests exercise
offset chaining, name decoding, unit conversion and the idle-process exclusion without the
kernel. The layout itself is validated against the live process table in
tests/integration/windows.
"""

import ctypes
from datetime import UTC, datetime

import pytest

from windows_medic.infrastructure.windows.nt_process_enumeration import (
    EPOCH_AS_FILETIME,
    INITIAL_BUFFER_BYTES,
    MAX_QUERY_ATTEMPTS,
    STATUS_INFO_LENGTH_MISMATCH,
    SYSTEM_PROCESS_INFORMATION_CLASS,
    SystemProcessInformation,
    enumerate_processes,
    filetime_to_datetime,
    parse_process_information,
    query_system_process_information,
)

FILETIME_TICKS_PER_SECOND = 10_000_000


class Entry:
    """Keeps the ctypes structure and its name buffer alive together."""

    def __init__(
        self,
        pid: int,
        *,
        name: str = "proc.exe",
        parent_pid: int = 4,
        create_ticks: int = EPOCH_AS_FILETIME,
        user_ticks: int = 0,
        kernel_ticks: int = 0,
        threads: int = 1,
        handles: int = 10,
        working_set: int = 1000,
        private: int = 800,
        read_bytes: int = 5,
        write_bytes: int = 6,
        session_id: int = 1,
    ) -> None:
        self.name_buffer = ctypes.create_unicode_buffer(name)
        self.struct = SystemProcessInformation()
        self.struct.NumberOfThreads = threads
        self.struct.CreateTime = create_ticks
        self.struct.UserTime = user_ticks
        self.struct.KernelTime = kernel_ticks
        self.struct.ImageName.Length = len(name) * 2
        self.struct.ImageName.MaximumLength = (len(name) + 1) * 2
        self.struct.ImageName.Buffer = ctypes.addressof(self.name_buffer) if name else None
        self.struct.UniqueProcessId = pid
        self.struct.InheritedFromUniqueProcessId = parent_pid
        self.struct.HandleCount = handles
        self.struct.SessionId = session_id
        self.struct.WorkingSetSize = working_set
        self.struct.PrivatePageCount = private
        self.struct.ReadTransferCount = read_bytes
        self.struct.WriteTransferCount = write_bytes


def chain(*entries: Entry, trailing_garbage: bytes = b"") -> ctypes.Array[ctypes.c_char]:
    size = ctypes.sizeof(SystemProcessInformation)
    blob = bytearray()
    for index, entry in enumerate(entries):
        entry.struct.NextEntryOffset = size if index < len(entries) - 1 else 0
        blob += bytes(entry.struct)
    blob += trailing_garbage
    return ctypes.create_string_buffer(bytes(blob), len(blob))


class TestParse:
    def test_maps_every_field_of_every_chained_entry(self) -> None:
        first = Entry(
            100,
            name="node.exe",
            parent_pid=50,
            create_ticks=EPOCH_AS_FILETIME + 90 * FILETIME_TICKS_PER_SECOND,
            user_ticks=15_000_000,
            kernel_ticks=5_000_000,
            threads=7,
            handles=321,
            working_set=4096,
            private=2048,
            read_bytes=11,
            write_bytes=22,
            session_id=2,
        )
        second = Entry(200, name="svchost.exe")
        buffer = chain(first, second)

        entries = parse_process_information(buffer)

        assert [e.pid for e in entries] == [100, 200]
        node = entries[0]
        assert node.parent_pid == 50
        assert node.image_name == "node.exe"
        assert node.create_time == datetime(1970, 1, 1, 0, 1, 30, tzinfo=UTC)
        assert node.cpu_time_seconds == 2.0
        assert node.thread_count == 7
        assert node.handle_count == 321
        assert node.working_set_bytes == 4096
        assert node.private_bytes == 2048
        assert node.io_read_bytes == 11
        assert node.io_write_bytes == 22
        assert node.session_id == 2
        assert entries[1].image_name == "svchost.exe"

    def test_idle_pseudo_process_is_not_an_entry(self) -> None:
        buffer = chain(Entry(0, name=""), Entry(4, name="System"))

        assert [e.pid for e in parse_process_information(buffer)] == [4]

    def test_empty_image_name_decodes_to_empty_string(self) -> None:
        buffer = chain(Entry(4, name=""))

        assert parse_process_information(buffer)[0].image_name == ""

    def test_stops_at_the_last_entry_and_ignores_trailing_bytes(self) -> None:
        buffer = chain(Entry(1), Entry(2), trailing_garbage=b"\xff" * 64)

        assert [e.pid for e in parse_process_information(buffer)] == [1, 2]

    def test_offset_running_past_the_buffer_ends_parsing_safely(self) -> None:
        entry = Entry(1)
        entry.struct.NextEntryOffset = 10**6
        truncated = ctypes.create_string_buffer(bytes(entry.struct), ctypes.sizeof(entry.struct))

        assert [e.pid for e in parse_process_information(truncated)] == [1]

    def test_buffer_smaller_than_one_entry_yields_nothing(self) -> None:
        assert parse_process_information(ctypes.create_string_buffer(b"\x00" * 8, 8)) == []


class TestFiletime:
    def test_unix_epoch(self) -> None:
        assert filetime_to_datetime(EPOCH_AS_FILETIME) == datetime(1970, 1, 1, tzinfo=UTC)

    def test_keeps_microsecond_precision(self) -> None:
        ticks = EPOCH_AS_FILETIME + 12_345_678  # 1.2345678 s

        assert filetime_to_datetime(ticks) == datetime(1970, 1, 1, 0, 0, 1, 234_567, tzinfo=UTC)


class TestEnumerate:
    def test_uses_the_injected_query(self) -> None:
        buffer = chain(Entry(77, name="x.exe"))

        entries = enumerate_processes(query=lambda: buffer)

        assert [e.pid for e in entries] == [77]

    def test_query_failure_propagates_as_os_error(self) -> None:
        def failing() -> ctypes.Array[ctypes.c_char]:
            raise OSError("NtQuerySystemInformation failed")

        with pytest.raises(OSError, match="NtQuerySystemInformation"):
            enumerate_processes(query=failing)


class FakeNtdll:
    """Scripted NTSTATUS results for NtQuerySystemInformation; fills nothing."""

    def __init__(self, statuses: list[int], needed: int = 0) -> None:
        self._statuses = list(statuses)
        self._needed = needed
        self.sizes: list[int] = []

    def NtQuerySystemInformation(  # noqa: N802 - Win32 export name
        self,
        information_class: int,
        buffer: ctypes.Array[ctypes.c_char],
        size: int,
        needed: "ctypes._Pointer[ctypes.c_ulong]",
    ) -> int:
        assert information_class == SYSTEM_PROCESS_INFORMATION_CLASS
        assert ctypes.sizeof(buffer) == size
        self.sizes.append(size)
        needed.contents.value = self._needed
        return self._statuses.pop(0)


class TestQueryBufferGrowth:
    def test_grows_the_buffer_on_length_mismatch_and_returns_the_final_buffer(self) -> None:
        mismatch = ctypes.c_long(STATUS_INFO_LENGTH_MISMATCH).value
        ntdll = FakeNtdll([mismatch, 0], needed=5 * INITIAL_BUFFER_BYTES)

        buffer = query_system_process_information(ntdll=ntdll)

        assert len(ntdll.sizes) == 2
        assert ntdll.sizes[1] > ntdll.sizes[0]
        assert ctypes.sizeof(buffer) == ntdll.sizes[1]

    def test_other_ntstatus_failures_raise_os_error(self) -> None:
        ntdll = FakeNtdll([ctypes.c_long(0xC0000005).value])

        with pytest.raises(OSError, match="0xC0000005"):
            query_system_process_information(ntdll=ntdll)

    def test_gives_up_after_bounded_attempts(self) -> None:
        mismatch = ctypes.c_long(STATUS_INFO_LENGTH_MISMATCH).value
        ntdll = FakeNtdll([mismatch] * MAX_QUERY_ATTEMPTS)

        with pytest.raises(OSError, match="kept growing"):
            query_system_process_information(ntdll=ntdll)

        assert len(ntdll.sizes) == MAX_QUERY_ATTEMPTS
