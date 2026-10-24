"""Win32HungWindowReader against a test-owned window that stops pumping messages."""

import ctypes
import subprocess
import sys
import time
from collections.abc import Iterator
from ctypes import wintypes
from pathlib import Path

import pytest

from windows_medic.infrastructure.windows.hung_window_reader import Win32HungWindowReader

pytestmark = pytest.mark.windows_integration

INTERPRETER = getattr(sys, "_base_executable", sys.executable)
CHILD_SCRIPT = Path(__file__).with_name("hung_window_child.py")
WM_NULL = 0x0000
SMTO_ABORTIFHUNG = 0x0002
HUNG_VERDICT_DEADLINE_SECONDS = 20.0  # Windows flags a window after ~5 s without message processing


@pytest.fixture
def hung_child() -> Iterator[tuple[subprocess.Popen[str], int]]:
    child = subprocess.Popen(
        [INTERPRETER, str(CHILD_SCRIPT)],
        stdout=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert child.stdout is not None
        hwnd = int(child.stdout.readline().strip())
        assert hwnd
        yield child, hwnd
    finally:
        child.terminate()
        child.wait(timeout=30)
        if child.stdout is not None:
            child.stdout.close()


def test_a_window_that_stops_pumping_messages_is_reported_as_hung(
    hung_child: tuple[subprocess.Popen[str], int],
) -> None:
    child, hwnd = hung_child
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    # Deliver a message the child will never process; Windows then applies its own
    # not-responding rule. The reader is polled, bounded, until the verdict appears.
    user32.SendMessageTimeoutW(
        wintypes.HWND(hwnd), WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 100, ctypes.byref(wintypes.DWORD())
    )
    reader = Win32HungWindowReader()

    deadline = time.monotonic() + HUNG_VERDICT_DEADLINE_SECONDS
    ours = []
    while time.monotonic() < deadline:
        ours = [w for w in reader.hung_windows() if w.owner_pid == child.pid]
        if ours:
            break
        time.sleep(0.5)

    assert ours, "the test-owned window was not reported hung in time"
    assert ours[0].title == "windows-medic hung test"


def test_reader_never_raises_on_the_real_desktop() -> None:
    windows = Win32HungWindowReader(limit=4).hung_windows()

    assert len(windows) <= 4
    assert all(w.owner_pid > 0 for w in windows)
