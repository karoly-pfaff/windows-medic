""":class:`ComponentController` for Windows: start Explorer from its fixed system location.

The only thing this adapter can start is ``<windows_directory>\\explorer.exe`` with no
arguments (as an argument array, detached from our console). DWM is refused: Windows
recreates it, Windows Medic never launches one.
"""

import subprocess
from collections.abc import Callable
from pathlib import Path

from windows_medic.domain.models.component import StartAttempt, WindowsComponent
from windows_medic.domain.policies.component_recovery import component_recipe

DETACHED_PROCESS = 0x0000_0008
CREATE_NEW_PROCESS_GROUP = 0x0000_0200


def spawn_detached(command: list[str]) -> int:
    """Start *command* (an argument array, never a shell string) and return its PID."""
    child = subprocess.Popen(  # noqa: S603 - fixed system path, argument array, no shell
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
    )
    # The child is deliberately fire-and-forget (a shell outlives us); mark the handle as
    # done so Popen's finalizer does not warn about a running child nobody will reap.
    child.returncode = 0
    return child.pid


class WindowsComponentController:
    def __init__(
        self, *, windows_directory: Path, spawn: Callable[[list[str]], int] = spawn_detached
    ) -> None:
        self._windows_directory = windows_directory
        self._spawn = spawn

    def start(self, component: WindowsComponent) -> StartAttempt:
        if not component_recipe(component).may_start:
            return StartAttempt(None, f"{component.image_name} is never started by Windows Medic")
        executable = self._windows_directory / component.image_name
        if not executable.is_file():
            return StartAttempt(None, f"{executable} not found")
        try:
            return StartAttempt(self._spawn([str(executable)]))
        except OSError as exc:
            return StartAttempt(None, f"start failed: {exc}")
