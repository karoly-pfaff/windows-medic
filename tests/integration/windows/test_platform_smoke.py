"""Windows integration smoke: the foundation runs on the real machine.

These tests read the real environment and run the installed console scripts. They create
no processes other than the project's own entry points and mutate nothing.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import windows_medic
from windows_medic.infrastructure.config.settings import default_data_dir

pytestmark = pytest.mark.windows_integration

CONSOLE_SCRIPTS = ("windows-medic", "windows-medic-agent", "windows-medic-mcp")


def test_runs_on_windows() -> None:
    assert sys.platform == "win32"


def test_default_data_dir_resolves_under_real_localappdata() -> None:
    data_dir = default_data_dir(os.environ)

    assert data_dir == Path(os.environ["LOCALAPPDATA"]) / "WindowsMedic"


@pytest.mark.parametrize("script", CONSOLE_SCRIPTS)
def test_installed_console_script_reports_its_version(script: str) -> None:
    executable = Path(sys.executable).parent / f"{script}.exe"
    assert executable.is_file(), f"{executable} missing: run `uv sync --all-groups`"

    completed = subprocess.run(
        [str(executable), "--version"], capture_output=True, text=True, check=False, timeout=60
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"{script} {windows_medic.__version__}"


def test_health_command_measures_the_real_machine(tmp_path: Path) -> None:
    executable = Path(sys.executable).parent / "windows-medic.exe"
    environ = {**os.environ, "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data")}

    completed = subprocess.run(
        [str(executable), "health"],
        capture_output=True,
        text=True,
        check=False,
        env=environ,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith("System health (measured over 1.0 s")
    assert "logical processors" in completed.stdout
    assert "Top CPU" in completed.stdout
    assert "Top memory" in completed.stdout
    assert completed.stdout.count("\n") < 40, "output must stay bounded"
