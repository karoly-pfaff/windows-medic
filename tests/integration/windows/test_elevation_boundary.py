"""The elevation boundary against the real helper executable, without ever elevating.

The helper is run unelevated as an ordinary child process; every case below is one the
helper must refuse before touching anything, so nothing on the machine is mutated.
"""

import io
import os
import subprocess
import sys
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from windows_medic.domain.models.component import WindowsComponent
from windows_medic.domain.models.elevation import (
    ElevatedOutcome,
    ElevatedRecipe,
    ElevatedRejection,
    ElevatedRequest,
)
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import RejectionReason, RepairStatus, RiskLevel
from windows_medic.domain.policies.component_recovery import (
    select_component_instance,
    session_of,
)
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic.infrastructure.windows.elevation_helper import helper_executable
from windows_medic.infrastructure.windows.elevation_launcher import (
    Launch,
    LaunchOutcome,
    UacElevationLauncher,
)
from windows_medic.infrastructure.windows.elevation_protocol import decode_result, encode_request
from windows_medic.infrastructure.windows.windows_process_reader import WindowsProcessReader
from windows_medic_root.container import compose

pytestmark = pytest.mark.windows_integration

# The only names the helper writes (it runs as administrator): elevated-<uuid hex>.json.
RESULT_NAME = f"elevated-{'ab' * 16}.json"

INTERPRETER = getattr(sys, "_base_executable", sys.executable)
SLEEPER = "import time; time.sleep(120)"


@pytest.fixture
def sleeper() -> Iterator[ProcessIdentity]:
    child = subprocess.Popen(
        [INTERPRETER, "-c", SLEEPER],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        reader = WindowsProcessReader(SystemClock())
        [match] = [o for o in reader.snapshot().processes if o.identity.pid == child.pid]
        yield match.identity
    finally:
        child.terminate()
        child.wait(timeout=30)


def run_helper(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(helper_executable()), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def own_session() -> int:
    session = session_of(WindowsProcessReader(SystemClock()).snapshot(), os.getpid())
    assert session is not None
    return session


class TestHelperExecutable:
    def test_exists_next_to_the_interpreter(self) -> None:
        assert helper_executable().is_file()

    def test_an_arbitrary_command_is_rejected_and_reported(self, tmp_path: Path) -> None:
        result_path = tmp_path / RESULT_NAME

        completed = run_helper(["cmd.exe", "/c", "whoami", "--result", str(result_path)])

        assert completed.returncode == 2, completed.stderr
        decoded = decode_result(result_path.read_text(encoding="utf-8"))
        assert decoded is not None
        assert decoded.outcome is ElevatedOutcome.REJECTED
        assert decoded.rejection is ElevatedRejection.UNKNOWN_RECIPE

    def test_malformed_arguments_are_rejected(self, tmp_path: Path) -> None:
        result_path = tmp_path / RESULT_NAME

        completed = run_helper(
            ["windows.dwm.terminate", "--pid", "notanumber", "--result", str(result_path)]
        )

        assert completed.returncode == 2
        decoded = decode_result(result_path.read_text(encoding="utf-8"))
        assert decoded is not None
        assert decoded.rejection is ElevatedRejection.MALFORMED_ARGUMENTS

    def test_a_process_that_is_not_dwm_is_refused_untouched(
        self, sleeper: ProcessIdentity, tmp_path: Path
    ) -> None:
        result_path = tmp_path / RESULT_NAME
        request = ElevatedRequest(ElevatedRecipe.WINDOWS_DWM_TERMINATE, sleeper, own_session())

        completed = run_helper(encode_request(request, result_path))

        assert completed.returncode == 2, completed.stderr
        decoded = decode_result(result_path.read_text(encoding="utf-8"))
        assert decoded is not None
        assert decoded.rejection is ElevatedRejection.NOT_THE_COMPONENT
        assert WindowsProcessReader(SystemClock()).get(sleeper) is not None

    def test_the_real_dwm_in_another_session_is_refused_before_any_call(
        self, tmp_path: Path
    ) -> None:
        reader = WindowsProcessReader(SystemClock())
        snapshot = reader.snapshot()
        session = session_of(snapshot, os.getpid())
        assert session is not None
        dwm = select_component_instance(snapshot, WindowsComponent.DWM, session=session)
        assert dwm is not None
        result_path = tmp_path / RESULT_NAME
        request = ElevatedRequest(
            ElevatedRecipe.WINDOWS_DWM_TERMINATE, dwm.identity, session + 1000
        )

        completed = run_helper(encode_request(request, result_path))

        assert completed.returncode == 2
        decoded = decode_result(result_path.read_text(encoding="utf-8"))
        assert decoded is not None
        assert decoded.rejection is ElevatedRejection.SESSION_MISMATCH
        assert reader.get(dwm.identity) is not None

    def test_a_missing_target_is_refused(self, tmp_path: Path) -> None:
        result_path = tmp_path / RESULT_NAME
        ghost = ProcessIdentity(4_000_000, SystemClock().now() - timedelta(days=1))
        request = ElevatedRequest(ElevatedRecipe.WINDOWS_DWM_TERMINATE, ghost, own_session())

        completed = run_helper(encode_request(request, result_path))

        assert completed.returncode == 2
        decoded = decode_result(result_path.read_text(encoding="utf-8"))
        assert decoded is not None
        assert decoded.rejection is ElevatedRejection.TARGET_NOT_FOUND


class TestLauncherProtocol:
    def test_the_launcher_reads_the_helper_result_through_the_file_protocol(
        self, sleeper: ProcessIdentity, tmp_path: Path
    ) -> None:
        def unelevated(executable: Path, parameters: list[str], timeout: timedelta) -> Launch:
            completed = subprocess.run(
                [str(executable), *parameters],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout.total_seconds(),
            )
            return Launch(LaunchOutcome.EXITED, exit_code=completed.returncode)

        launcher = UacElevationLauncher(
            helper=helper_executable(),
            result_dir=tmp_path / "elevated",
            timeout=timedelta(seconds=60),
            launch=unelevated,
        )

        result = launcher.run(
            ElevatedRequest(ElevatedRecipe.WINDOWS_DWM_TERMINATE, sleeper, own_session())
        )

        assert result.outcome is ElevatedOutcome.REJECTED
        assert result.rejection is ElevatedRejection.NOT_THE_COMPONENT
        assert list((tmp_path / "elevated").iterdir()) == []


class TestDwmGate:
    def test_dwm_restart_is_rejected_by_default_and_audited(
        self, tmp_path: Path, request: pytest.FixtureRequest
    ) -> None:
        environ = {**os.environ, "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data")}
        container = compose(environ=environ, log_stream=io.StringIO())
        request.addfinalizer(container.close)
        reader = WindowsProcessReader(SystemClock())
        session = session_of(reader.snapshot(), os.getpid())
        assert session is not None

        record = container.restart_windows_component.execute(WindowsComponent.DWM)

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.HIGH_RISK_DISABLED
        assert record.risk is RiskLevel.HIGH
        assert record.requires_elevation is True
        assert record.target is not None
        assert reader.get(record.target) is not None  # the session's DWM is untouched
        assert container.list_recent_repairs.execute()[0].id == record.id

    def test_the_session_has_an_explorer_and_a_dwm_instance(self) -> None:
        snapshot = WindowsProcessReader(SystemClock()).snapshot()
        session = session_of(snapshot, os.getpid())
        assert session is not None

        explorer = select_component_instance(snapshot, WindowsComponent.EXPLORER, session=session)
        dwm = select_component_instance(snapshot, WindowsComponent.DWM, session=session)

        assert explorer is not None
        assert dwm is not None
        assert explorer.name == "explorer.exe"
        assert dwm.name == "dwm.exe"
