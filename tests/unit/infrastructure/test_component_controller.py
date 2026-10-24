"""WindowsComponentController: Explorer from its fixed location only; DWM never."""

from pathlib import Path

from windows_medic.domain.models.component import WindowsComponent
from windows_medic.infrastructure.windows.component_controller import (
    WindowsComponentController,
)


def test_explorer_is_started_from_the_windows_directory_with_no_arguments(
    tmp_path: Path,
) -> None:
    (tmp_path / "explorer.exe").write_bytes(b"")
    seen: list[list[str]] = []

    def spawn(command: list[str]) -> int:
        seen.append(command)
        return 4321

    controller = WindowsComponentController(windows_directory=tmp_path, spawn=spawn)

    attempt = controller.start(WindowsComponent.EXPLORER)

    assert attempt.pid == 4321
    assert seen == [[str(tmp_path / "explorer.exe")]]


def test_dwm_is_refused_before_any_lookup(tmp_path: Path) -> None:
    controller = WindowsComponentController(windows_directory=tmp_path, spawn=_never)

    attempt = controller.start(WindowsComponent.DWM)

    assert attempt.pid is None
    assert attempt.detail == "dwm.exe is never started by Windows Medic"


def test_a_missing_executable_is_reported(tmp_path: Path) -> None:
    controller = WindowsComponentController(windows_directory=tmp_path, spawn=_never)

    attempt = controller.start(WindowsComponent.EXPLORER)

    assert attempt.pid is None
    assert attempt.detail == f"{tmp_path / 'explorer.exe'} not found"


def test_a_spawn_failure_is_reported(tmp_path: Path) -> None:
    (tmp_path / "explorer.exe").write_bytes(b"")

    def failing(command: list[str]) -> int:
        raise OSError(5, "access is denied")

    controller = WindowsComponentController(windows_directory=tmp_path, spawn=failing)

    attempt = controller.start(WindowsComponent.EXPLORER)

    assert attempt.pid is None
    assert attempt.detail == "start failed: [Errno 5] access is denied"


def _never(command: list[str]) -> int:
    raise AssertionError(f"must not spawn {command}")
