"""Win32 hung-window enumeration against a shape-compatible fake user32."""

import ctypes
import io
import json
import logging
from collections.abc import Callable, Iterator
from ctypes import wintypes

import pytest

from windows_medic.domain.models.gui import HungWindow
from windows_medic.infrastructure.config.settings import LogLevel
from windows_medic.infrastructure.observability.structured_logging import configure_logging
from windows_medic.infrastructure.windows.hung_window_reader import (
    Win32HungWindowReader,
    enumerate_hung_windows,
)


class FakeUser32:
    """Scripted top-level windows: ``(hwnd, pid, title, visible, hung)``."""

    def __init__(self, *windows: tuple[int, int, str, bool, bool]) -> None:
        self._windows = {w[0]: w for w in windows}
        self.stop_after: int | None = None

    def EnumWindows(self, callback: Callable[[int, int], int], lparam: int) -> int:  # noqa: N802
        for hwnd in self._windows:
            if not callback(hwnd, lparam):
                return 1
        return 1

    def IsWindowVisible(self, hwnd: int) -> int:  # noqa: N802
        return int(self._windows[hwnd][3])

    def IsHungAppWindow(self, hwnd: int) -> int:  # noqa: N802
        return int(self._windows[hwnd][4])

    def GetWindowThreadProcessId(  # noqa: N802
        self, hwnd: int, pid: "ctypes._Pointer[wintypes.DWORD]"
    ) -> int:
        pid.contents.value = self._windows[hwnd][1]
        return 7

    def GetWindowTextW(  # noqa: N802
        self, hwnd: int, buffer: ctypes.Array[ctypes.c_wchar], count: int
    ) -> int:
        title = self._windows[hwnd][2][: count - 1]
        buffer.value = title
        return len(title)


def test_only_visible_hung_windows_are_reported_with_bounded_titles() -> None:
    user32 = FakeUser32(
        (1, 100, "Responsive", True, False),
        (2, 200, "Frozen editor - a very long title indeed", True, True),
        (3, 300, "Hidden and hung", False, True),
        (4, 200, "", True, True),
    )

    windows = enumerate_hung_windows(user32=user32, limit=10, max_title=12)

    assert windows == (HungWindow(200, "Frozen edito"), HungWindow(200, ""))


def test_enumeration_stops_at_the_limit() -> None:
    user32 = FakeUser32(*((n, n, f"w{n}", True, True) for n in range(1, 6)))

    windows = enumerate_hung_windows(user32=user32, limit=2, max_title=32)

    assert [w.owner_pid for w in windows] == [1, 2]


def test_windows_with_an_unknown_owner_are_skipped() -> None:
    user32 = FakeUser32((1, 0, "orphan", True, True), (2, 5, "ok", True, True))

    windows = enumerate_hung_windows(user32=user32, limit=10, max_title=32)

    assert windows == (HungWindow(5, "ok"),)


def test_enumeration_failure_raises_os_error() -> None:
    class Failing(FakeUser32):
        def EnumWindows(self, callback: Callable[[int, int], int], lparam: int) -> int:  # noqa: N802
            ctypes.set_last_error(5)
            return 0

    with pytest.raises(OSError, match="denied"):
        enumerate_hung_windows(user32=Failing(), limit=10, max_title=32)


@pytest.fixture
def log_stream() -> Iterator[io.StringIO]:
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    stream = io.StringIO()
    configure_logging(LogLevel.INFO, stream)
    yield stream
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def test_reader_reports_nothing_and_logs_when_enumeration_fails(log_stream: io.StringIO) -> None:
    def failing(*, limit: int, max_title: int) -> tuple[HungWindow, ...]:
        raise OSError(5, "access denied")

    reader = Win32HungWindowReader(enumerate_windows=failing)

    assert reader.hung_windows() == ()
    events = [json.loads(line) for line in log_stream.getvalue().splitlines()]
    assert [e["event"] for e in events] == ["hung_windows.unavailable"]


def test_reader_passes_its_bounds_to_the_enumeration() -> None:
    seen: list[tuple[int, int]] = []

    def scripted(*, limit: int, max_title: int) -> tuple[HungWindow, ...]:
        seen.append((limit, max_title))
        return (HungWindow(9, "x"),)

    reader = Win32HungWindowReader(limit=3, max_title=40, enumerate_windows=scripted)

    assert reader.hung_windows() == (HungWindow(9, "x"),)
    assert seen == [(3, 40)]


def test_enumeration_that_stops_without_an_error_is_not_a_failure() -> None:
    class Stopping(FakeUser32):
        def EnumWindows(self, callback: Callable[[int, int], int], lparam: int) -> int:  # noqa: N802
            ctypes.set_last_error(0)
            return 0

    assert enumerate_hung_windows(user32=Stopping(), limit=10, max_title=32) == ()
