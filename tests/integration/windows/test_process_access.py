"""The handle-free path and the limited-access probe agree with what psutil reports."""

import os

import psutil
import pytest

from windows_medic.infrastructure.windows.process_access import (
    ProcessGoneError,
    image_path_without_handle,
    may_open_limited,
)

pytestmark = pytest.mark.windows_integration

# Enough to cover protected services and session processes on any machine, bounded.
_MAX_COMPARED = 40


def test_our_own_process_is_open_to_us_and_its_path_is_the_interpreter() -> None:
    assert may_open_limited(os.getpid()) is True
    assert image_path_without_handle(os.getpid()).lower() == psutil.Process().exe().lower()


def test_denied_processes_get_the_same_path_psutil_finds_without_a_handle() -> None:
    denied = [pid for pid in psutil.pids() if pid > 4 and not may_open_limited(pid)]
    if not denied:
        pytest.skip("no process denies limited access (running elevated?)")

    compared = 0
    for pid in denied[:_MAX_COMPARED]:
        try:
            ours = image_path_without_handle(pid)
            theirs = psutil.Process(pid).exe()
        except (ProcessGoneError, psutil.NoSuchProcess):
            continue  # exited between the two reads
        assert ours.lower() == theirs.lower(), pid
        compared += 1

    assert compared > 0


def test_a_pid_that_does_not_exist_is_reported_gone() -> None:
    unused = max(psutil.pids()) + 4 * 1024 * 1024
    with pytest.raises(ProcessGoneError):
        image_path_without_handle(unused)
    assert may_open_limited(unused) is True  # not "denied": the caller reports it gone


def test_the_kernel_process_has_no_image_path() -> None:
    assert image_path_without_handle(4) == ""
