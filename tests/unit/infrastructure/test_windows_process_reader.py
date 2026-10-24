"""WindowsProcessReader combines the kernel inventory with per-handle psutil fields.

The kernel enumeration and psutil are replaced by shape-compatible fakes so races and
denials are reproducible. The real adapter is exercised in tests/integration/windows.
"""

import itertools
import threading
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from typing import Self, cast

import psutil
import pytest

from tests.fakes import FakeClock
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.infrastructure.windows.nt_process_enumeration import NtProcessEntry
from windows_medic.infrastructure.windows.process_access import ProcessGoneError
from windows_medic.infrastructure.windows.windows_process_reader import (
    ProcessInventoryError,
    WindowsProcessReader,
)

T0 = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)
CREATED = T0 - timedelta(minutes=5)


def entry(pid: int, *, created: datetime = CREATED, name: str = "proc.exe") -> NtProcessEntry:
    return NtProcessEntry(
        pid=pid,
        parent_pid=4,
        create_time=created,
        cpu_time_seconds=2.0,
        thread_count=3,
        handle_count=50,
        working_set_bytes=1000,
        private_bytes=800,
        io_read_bytes=10,
        io_write_bytes=20,
        session_id=1,
        image_name=name,
    )


class FakePsutilProcess:
    """The per-handle subset of ``psutil.Process``; any field may raise on demand."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self._failures: dict[str, Exception] = {}
        self._overrides: dict[str, object] = {}

    def failing(self, field: str, error: Exception) -> Self:
        self._failures[field] = error
        return self

    def returning(self, field: str, value: object) -> Self:
        self._overrides[field] = value
        return self

    def _value[T](self, field: str, value: T) -> T:
        if field in self._failures:
            raise self._failures[field]
        if field in self._overrides:
            return cast("T", self._overrides[field])
        return value

    def oneshot(self) -> nullcontext[None]:
        return nullcontext()

    def exe(self) -> str:
        return self._value("exe", f"C:\\bin\\proc{self.pid}.exe")

    def cmdline(self) -> list[str]:
        return self._value("cmdline", [f"proc{self.pid}.exe", "--flag"])

    def username(self) -> str:
        return self._value("username", "DESKTOP\\user")


class FakeSources:
    def __init__(
        self,
        *entries: NtProcessEntry,
        handles: dict[int, FakePsutilProcess] | None = None,
        gone_at_open: set[int] | None = None,
        denied: dict[int, str | OSError] | None = None,
    ) -> None:
        self._entries = list(entries)
        self._handles = handles or {}
        self._gone = gone_at_open or set()
        # pid -> what the handle-free image query answers for a process that denies access
        self.denied = denied or {}
        self.opened: list[int] = []

    def enumerate(self) -> list[NtProcessEntry]:
        return list(self._entries)

    def process(self, pid: int) -> FakePsutilProcess:
        self.opened.append(pid)
        if pid in self._gone:
            raise psutil.NoSuchProcess(pid)
        return self._handles.get(pid, FakePsutilProcess(pid))

    def may_open(self, pid: int) -> bool:
        return pid not in self.denied

    def image_path(self, pid: int) -> str:
        answer = self.denied[pid]
        if isinstance(answer, OSError):
            raise answer
        return answer


def reader(sources: FakeSources) -> WindowsProcessReader:
    return WindowsProcessReader(
        clock=FakeClock(T0),
        inventory=sources.enumerate,
        process=sources.process,
        may_open=sources.may_open,
        image_path=sources.image_path,
    )


class TestSnapshot:
    def test_maps_kernel_and_handle_fields(self) -> None:
        snapshot = reader(FakeSources(entry(42, name="node.exe"))).snapshot()

        [observation] = snapshot.processes
        assert observation.identity == ProcessIdentity(42, CREATED)
        assert observation.observed_at == T0
        assert observation.name == "node.exe"
        assert observation.exe_path == "C:\\bin\\proc42.exe"
        assert observation.command_line == ("proc42.exe", "--flag")
        assert observation.parent_pid == 4
        assert observation.username == "DESKTOP\\user"
        assert observation.session_id == 1
        assert observation.cpu_time_seconds == 2.0
        assert observation.working_set_bytes == 1000
        assert observation.private_bytes == 800
        assert observation.io_read_bytes == 10
        assert observation.io_write_bytes == 20
        assert observation.thread_count == 3
        assert observation.handle_count == 50
        assert snapshot.observed_at == T0
        assert snapshot.skipped_count == 0

    def test_all_observations_share_the_enumeration_instant(self) -> None:
        snapshot = reader(FakeSources(entry(1), entry(2))).snapshot()

        assert {o.observed_at for o in snapshot.processes} == {T0}

    def test_process_exiting_before_its_handle_opens_keeps_kernel_facts(self) -> None:
        snapshot = reader(FakeSources(entry(9), gone_at_open={9})).snapshot()

        [observation] = snapshot.processes
        gone = Unavailable(UnavailableReason.PROCESS_GONE)
        assert observation.identity.pid == 9
        assert observation.name == "proc.exe"
        assert observation.working_set_bytes == 1000
        assert observation.exe_path == gone
        assert observation.command_line == gone
        assert observation.username == gone

    def test_denied_handle_fields_are_access_denied(self) -> None:
        protected = (
            FakePsutilProcess(4)
            .failing("exe", psutil.AccessDenied(4))
            .failing("cmdline", psutil.AccessDenied(4))
        )

        [observation] = reader(FakeSources(entry(4), handles={4: protected})).snapshot().processes

        denied = Unavailable(UnavailableReason.ACCESS_DENIED)
        assert observation.exe_path == denied
        assert observation.command_line == denied
        assert observation.username == "DESKTOP\\user"

    def test_kernel_processes_without_image_path_or_command_line_are_not_faked(self) -> None:
        system = FakePsutilProcess(4).returning("exe", "").returning("cmdline", [])

        [observation] = (
            reader(FakeSources(entry(4, name="System"), handles={4: system})).snapshot().processes
        )

        unsupported = Unavailable(UnavailableReason.NOT_SUPPORTED)
        assert observation.exe_path == unsupported
        assert observation.command_line == unsupported

    def test_process_exiting_mid_read_marks_remaining_fields_gone(self) -> None:
        exiting = FakePsutilProcess(9).failing("cmdline", psutil.NoSuchProcess(9))

        [observation] = reader(FakeSources(entry(9), handles={9: exiting})).snapshot().processes

        assert observation.exe_path == "C:\\bin\\proc9.exe"
        assert observation.command_line == Unavailable(UnavailableReason.PROCESS_GONE)

    @pytest.mark.parametrize("error", [OSError("RPC failed"), psutil.Error()])
    def test_other_failures_are_unavailable_with_error(self, error: Exception) -> None:
        flaky = FakePsutilProcess(5).failing("username", error)

        [observation] = reader(FakeSources(entry(5), handles={5: flaky})).snapshot().processes

        assert observation.username == Unavailable(UnavailableReason.ERROR)

    def test_one_failing_process_never_hides_the_others(self) -> None:
        sources = FakeSources(
            entry(1),
            entry(2),
            entry(3),
            handles={2: FakePsutilProcess(2).failing("exe", psutil.AccessDenied(2))},
            gone_at_open={3},
        )

        snapshot = reader(sources).snapshot()

        assert [p.identity.pid for p in snapshot.processes] == [1, 2, 3]

    def test_failed_enumeration_is_a_typed_error(self) -> None:
        def failing() -> list[NtProcessEntry]:
            raise OSError("NTSTATUS 0xC0000005")

        with pytest.raises(ProcessInventoryError, match="0xC0000005"):
            WindowsProcessReader(
                clock=FakeClock(T0),
                inventory=failing,
                process=FakePsutilProcess,
                may_open=lambda _pid: True,
            ).snapshot()


class TestDeniedProcesses:
    """A process that denies limited query access is never opened through psutil."""

    def test_the_image_path_comes_without_a_handle_and_the_rest_is_denied(self) -> None:
        sources = FakeSources(entry(8), denied={8: "C:\\Windows\\System32\\csrss.exe"})

        [observation] = reader(sources).snapshot().processes

        assert observation.exe_path == "C:\\Windows\\System32\\csrss.exe"
        assert observation.command_line == Unavailable(UnavailableReason.ACCESS_DENIED)
        assert observation.username == Unavailable(UnavailableReason.ACCESS_DENIED)
        assert sources.opened == []

    def test_a_kernel_process_without_an_image_has_no_path(self) -> None:
        [observation] = reader(FakeSources(entry(4), denied={4: ""})).snapshot().processes

        assert observation.exe_path == Unavailable(UnavailableReason.NOT_SUPPORTED)

    def test_a_process_gone_before_its_path_is_read_is_retried_later(self) -> None:
        sources = FakeSources(entry(9), denied={9: ProcessGoneError("gone")})
        under_test = reader(sources)

        [observation] = under_test.snapshot().processes

        assert observation.exe_path == Unavailable(UnavailableReason.PROCESS_GONE)
        assert under_test.cached_identities == 0

    def test_a_refused_path_query_is_an_error_not_a_crash(self) -> None:
        sources = FakeSources(entry(9), denied={9: OSError("NTSTATUS 0xC0000022")})

        [observation] = reader(sources).snapshot().processes

        assert observation.exe_path == Unavailable(UnavailableReason.ERROR)


class TestConcurrentUse:
    def test_snapshots_and_lookups_from_several_threads_never_corrupt_the_cache(self) -> None:
        # The MCP server runs tools on worker threads against one shared reader.
        generations = itertools.count()

        def churning() -> list[NtProcessEntry]:
            base = next(generations) * 50
            return [entry(pid) for pid in range(base, base + 50)]

        under_test = WindowsProcessReader(
            clock=FakeClock(T0),
            inventory=churning,
            process=FakePsutilProcess,
            may_open=lambda _pid: True,
        )
        errors: list[BaseException] = []

        def hammer() -> None:
            try:
                for _ in range(200):
                    under_test.snapshot()
                    under_test.get(ProcessIdentity(1, CREATED))
            except BaseException as exc:  # noqa: BLE001 - collected and asserted below
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert errors == []
        assert not any(thread.is_alive() for thread in threads)


class TestGetByIdentity:
    def test_returns_the_observation_when_identity_matches(self) -> None:
        observation = reader(FakeSources(entry(42))).get(ProcessIdentity(42, CREATED))

        assert observation is not None
        assert observation.identity == ProcessIdentity(42, CREATED)

    def test_returns_none_when_the_pid_now_belongs_to_a_different_process(self) -> None:
        stale = ProcessIdentity(42, CREATED - timedelta(hours=1))

        assert reader(FakeSources(entry(42))).get(stale) is None

    def test_returns_none_when_the_process_is_gone(self) -> None:
        assert reader(FakeSources()).get(ProcessIdentity(42, CREATED)) is None

    def test_does_not_open_handles_of_unrelated_processes(self) -> None:
        opened: list[int] = []

        def process(pid: int) -> FakePsutilProcess:
            opened.append(pid)
            return FakePsutilProcess(pid)

        WindowsProcessReader(
            clock=FakeClock(T0),
            inventory=lambda: [entry(1), entry(2), entry(3)],
            process=process,
            may_open=lambda _pid: True,
        ).get(ProcessIdentity(2, CREATED))

        assert opened == [2]


class CountingSources(FakeSources):
    def __init__(self, *entries: NtProcessEntry, **kwargs: object) -> None:
        super().__init__(*entries, **kwargs)  # type: ignore[arg-type]
        self._current = list(entries)

    def enumerate(self) -> list[NtProcessEntry]:
        return list(self._current)

    def now_running(self, *entries: NtProcessEntry) -> None:
        self._current = list(entries)


class TestHandleFieldCache:
    def test_immutable_handle_fields_are_read_once_per_identity(self) -> None:
        sources = CountingSources(entry(1), entry(2))
        under_test = reader(sources)

        first = under_test.snapshot()
        second = under_test.snapshot()

        assert sources.opened == [1, 2]
        assert [p.exe_path for p in second.processes] == [p.exe_path for p in first.processes]
        assert under_test.cached_identities == 2

    def test_a_reused_pid_is_a_new_identity_and_is_read_again(self) -> None:
        sources = CountingSources(entry(7, created=CREATED))
        under_test = reader(sources)
        under_test.snapshot()

        sources.now_running(entry(7, created=CREATED + timedelta(seconds=30)))
        under_test.snapshot()

        assert sources.opened == [7, 7]

    def test_entries_of_exited_processes_are_evicted(self) -> None:
        sources = CountingSources(entry(1), entry(2))
        under_test = reader(sources)
        under_test.snapshot()

        sources.now_running(entry(2))
        under_test.snapshot()

        assert under_test.cached_identities == 1

    def test_transient_failures_are_not_cached(self) -> None:
        sources = CountingSources(entry(9), gone_at_open={9})
        under_test = reader(sources)

        under_test.snapshot()
        sources._gone.clear()
        second = under_test.snapshot()

        assert sources.opened == [9, 9]
        assert second.processes[0].exe_path == "C:\\bin\\proc9.exe"

    def test_denied_and_unsupported_fields_are_stable_and_cached(self) -> None:
        protected = FakePsutilProcess(4).failing("exe", psutil.AccessDenied(4))
        protected.returning("cmdline", [])
        sources = CountingSources(entry(4, name="System"), handles={4: protected})
        under_test = reader(sources)

        under_test.snapshot()
        under_test.snapshot()

        assert sources.opened == [4]

    def test_get_uses_and_fills_the_cache(self) -> None:
        sources = CountingSources(entry(5))
        under_test = reader(sources)

        under_test.get(ProcessIdentity(5, CREATED))
        under_test.get(ProcessIdentity(5, CREATED))

        assert sources.opened == [5]
