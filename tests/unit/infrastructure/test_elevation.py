"""The elevation boundary: strict protocol, a helper that verifies before acting, a launcher
that turns every outcome into a typed result."""

import _winapi
import ctypes
import io
from ctypes import wintypes
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from tests.builders import BOOT, T0, identity, process, process_snapshot
from tests.fakes import FakeClock, FakeProcessReader, FakeProcessWorld
from windows_medic.domain.errors import ObservationError
from windows_medic.domain.models.elevation import (
    ElevatedOutcome,
    ElevatedRecipe,
    ElevatedRejection,
    ElevatedRequest,
    ElevatedResult,
)
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.repair import TerminationAttempt, TerminationOutcome
from windows_medic.domain.models.samples import ProcessSnapshot
from windows_medic.infrastructure.windows import elevation_helper
from windows_medic.infrastructure.windows.elevation_launcher import (
    ERROR_CANCELLED,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    Launch,
    LaunchOutcome,
    ShellExecuteInfoW,
    UacElevationLauncher,
    launch_as_administrator,
)
from windows_medic.infrastructure.windows.elevation_protocol import (
    decode_result,
    encode_request,
    encode_result,
    parse_request,
    result_path_of,
)

REQUEST = ElevatedRequest(ElevatedRecipe.WINDOWS_DWM_TERMINATE, identity(300), 1)
RESULT = Path("C:/wm/elevated-1.json")


def dwm(pid: int = 300, session: int = 1) -> ProcessObservation:
    return replace(process(pid, name="dwm.exe"), session_id=session)


RESULT_NAME = f"elevated-{'0' * 32}.json"


class TestProtocol:
    def test_a_request_round_trips_through_the_argument_array(self) -> None:
        argv = encode_request(REQUEST, RESULT)

        assert argv == [
            "windows.dwm.terminate",
            "--pid",
            "300",
            "--create-time",
            BOOT.isoformat(),
            "--session",
            "1",
            "--result",
            str(RESULT),
        ]
        assert parse_request(argv) == (REQUEST, RESULT)
        assert result_path_of(argv) == RESULT

    @pytest.mark.parametrize(
        ("argv", "expected"),
        [
            ([], ElevatedRejection.MALFORMED_ARGUMENTS),
            (["process.terminate", "--pid", "1"], ElevatedRejection.UNKNOWN_RECIPE),
            (["cmd.exe", "/c", "whoami"], ElevatedRejection.UNKNOWN_RECIPE),
            (["windows.dwm.terminate"], ElevatedRejection.MALFORMED_ARGUMENTS),
            (
                [
                    "windows.dwm.terminate",
                    "--pid",
                    "x",
                    "--create-time",
                    BOOT.isoformat(),
                    "--session",
                    "1",
                    "--result",
                    str(RESULT),
                ],
                ElevatedRejection.MALFORMED_ARGUMENTS,
            ),
            (
                [
                    "windows.dwm.terminate",
                    "--pid",
                    "1",
                    "--create-time",
                    "2026-09-11T09:00:00",
                    "--session",
                    "1",
                    "--result",
                    str(RESULT),
                ],
                ElevatedRejection.MALFORMED_ARGUMENTS,
            ),
            (
                [
                    "windows.dwm.terminate",
                    "--pid",
                    "1",
                    "--create-time",
                    BOOT.isoformat(),
                    "--session",
                    "1",
                    "--result",
                    "relative.json",
                ],
                ElevatedRejection.MALFORMED_ARGUMENTS,
            ),
            (
                [
                    "windows.dwm.terminate",
                    "--pid",
                    "1",
                    "--create-time",
                    BOOT.isoformat(),
                    "--session",
                    "1",
                    "--exe",
                    str(RESULT),
                ],
                ElevatedRejection.MALFORMED_ARGUMENTS,
            ),
            (
                [
                    "windows.dwm.terminate",
                    "--pid",
                    "-1",
                    "--create-time",
                    BOOT.isoformat(),
                    "--session",
                    "1",
                    "--result",
                    str(RESULT),
                ],
                ElevatedRejection.MALFORMED_ARGUMENTS,
            ),
        ],
    )
    def test_unknown_or_malformed_requests_are_rejected(
        self, argv: list[str], expected: ElevatedRejection
    ) -> None:
        assert parse_request(argv) is expected

    def test_result_path_extraction_is_best_effort_and_strict(self) -> None:
        assert result_path_of(["x", "--result"]) is None
        assert result_path_of(["x", "--result", "C:/wm/out.txt"]) is None
        assert result_path_of(["x"]) is None

    @pytest.mark.parametrize(
        "result",
        [
            ElevatedResult(
                ElevatedOutcome.COMPLETED, TerminationAttempt(TerminationOutcome.SIGNALLED)
            ),
            ElevatedResult(
                ElevatedOutcome.COMPLETED,
                TerminationAttempt(
                    TerminationOutcome.ACCESS_DENIED, "OpenProcess: access is denied"
                ),
            ),
            ElevatedResult(ElevatedOutcome.REJECTED, rejection=ElevatedRejection.NOT_THE_COMPONENT),
            ElevatedResult(ElevatedOutcome.FAILED, detail="boom"),
        ],
    )
    def test_results_round_trip_through_json(self, result: ElevatedResult) -> None:
        assert decode_result(encode_result(result)) == result

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "not json",
            "[]",
            '{"outcome": "weird"}',
            '{"nope": 1}',
            '{"outcome": "completed", "termination": {"detail": "x"}}',
            '{"outcome": "failed", "rejection": "bogus"}',
        ],
    )
    def test_unreadable_results_are_none(self, text: str) -> None:
        assert decode_result(text) is None


class TestHelper:
    def test_the_verified_component_is_terminated(self) -> None:
        world = FakeProcessWorld(FakeClock(T0), dwm())

        result = elevation_helper.perform(REQUEST, process_reader=world, terminate=world.terminate)

        assert result == ElevatedResult(
            ElevatedOutcome.COMPLETED, TerminationAttempt(TerminationOutcome.SIGNALLED)
        )
        assert world.terminations == [identity(300)]

    @pytest.mark.parametrize(
        ("processes", "asked", "expected"),
        [
            ((), REQUEST, ElevatedRejection.TARGET_NOT_FOUND),
            (
                (replace(process(300, name="dwm.exe", created=T0), session_id=1),),
                REQUEST,
                ElevatedRejection.STALE_IDENTITY,
            ),
            (
                (replace(process(300, name="python.exe"), session_id=1),),
                REQUEST,
                ElevatedRejection.NOT_THE_COMPONENT,
            ),
            ((dwm(300, session=2),), REQUEST, ElevatedRejection.SESSION_MISMATCH),
        ],
    )
    def test_anything_but_the_named_component_in_the_named_session_is_refused(
        self,
        processes: tuple[ProcessObservation, ...],
        asked: ElevatedRequest,
        expected: ElevatedRejection,
    ) -> None:
        world = FakeProcessWorld(FakeClock(T0), *processes)

        result = elevation_helper.perform(asked, process_reader=world, terminate=world.terminate)

        assert result.outcome is ElevatedOutcome.REJECTED
        assert result.rejection is expected
        assert world.terminations == []

    def test_an_inventory_failure_is_a_failure_not_a_traceback(self) -> None:
        class Broken(FakeProcessReader):
            def snapshot(self) -> ProcessSnapshot:
                raise ObservationError("enumeration failed")

        result = elevation_helper.perform(REQUEST, process_reader=Broken(), terminate=_never)

        assert result.outcome is ElevatedOutcome.FAILED
        assert result.detail == "process inventory failed: enumeration failed"

    def test_main_writes_the_result_file_and_exit_code(self, tmp_path: Path) -> None:
        world = FakeProcessWorld(FakeClock(T0), dwm())
        result_path = tmp_path / RESULT_NAME

        code = elevation_helper.main(
            encode_request(REQUEST, result_path),
            process_reader=world,
            terminate=world.terminate,
            stderr=io.StringIO(),
        )

        assert code == elevation_helper.EXIT_COMPLETED
        decoded = decode_result(result_path.read_text(encoding="utf-8"))
        assert decoded is not None
        assert decoded.outcome is ElevatedOutcome.COMPLETED

    def test_main_rejects_unknown_recipes_but_still_reports_when_it_can(
        self, tmp_path: Path
    ) -> None:
        result_path = tmp_path / RESULT_NAME
        stderr = io.StringIO()

        code = elevation_helper.main(
            ["cmd.exe", "/c", "whoami", "--result", str(result_path)],
            process_reader=FakeProcessReader(process_snapshot()),
            terminate=_never,
            stderr=stderr,
        )

        assert code == elevation_helper.EXIT_REJECTED
        decoded = decode_result(result_path.read_text(encoding="utf-8"))
        assert decoded is not None
        assert decoded.rejection is ElevatedRejection.UNKNOWN_RECIPE

    def test_main_without_a_result_path_reports_on_stderr(self) -> None:
        stderr = io.StringIO()

        code = elevation_helper.main(
            ["nonsense"], process_reader=FakeProcessReader(), terminate=_never, stderr=stderr
        )

        assert code == elevation_helper.EXIT_REJECTED
        assert '"rejection": "unknown_recipe"' in stderr.getvalue()

    def test_main_reports_an_unwritable_result_path(self, tmp_path: Path) -> None:
        stderr = io.StringIO()
        result_path = tmp_path / "missing-dir" / RESULT_NAME

        code = elevation_helper.main(
            encode_request(REQUEST, result_path),
            process_reader=FakeProcessReader(process_snapshot()),
            terminate=_never,
            stderr=stderr,
        )

        assert code == elevation_helper.EXIT_FAILED
        assert "cannot write result file" in stderr.getvalue()

    def test_main_contains_unexpected_errors(self, tmp_path: Path) -> None:
        class Exploding(FakeProcessReader):
            def snapshot(self) -> ProcessSnapshot:
                raise RuntimeError("kaboom")

        result_path = tmp_path / RESULT_NAME

        code = elevation_helper.main(
            encode_request(REQUEST, result_path),
            process_reader=Exploding(),
            terminate=_never,
            stderr=io.StringIO(),
        )

        assert code == elevation_helper.EXIT_FAILED
        decoded = decode_result(result_path.read_text(encoding="utf-8"))
        assert decoded is not None
        assert decoded.detail == "RuntimeError: kaboom"

    @pytest.mark.parametrize(
        "name", ["result.json", "elevated-xyz.json", f"elevated-{'0' * 32}.json.json"]
    )
    def test_main_writes_only_files_named_like_its_results(self, tmp_path: Path, name: str) -> None:
        # Running as administrator: the path comes from an unelevated caller.
        stderr = io.StringIO()

        code = elevation_helper.main(
            encode_request(REQUEST, tmp_path / name),
            process_reader=FakeProcessReader(process_snapshot()),
            terminate=_never,
            stderr=stderr,
        )

        assert code == elevation_helper.EXIT_FAILED
        assert not (tmp_path / name).exists()
        assert "not a result file name" in stderr.getvalue()

    def test_main_never_overwrites_an_existing_file(self, tmp_path: Path) -> None:
        existing = tmp_path / RESULT_NAME
        existing.write_text("someone else's", encoding="utf-8")
        stderr = io.StringIO()

        code = elevation_helper.main(
            encode_request(REQUEST, existing),
            process_reader=FakeProcessReader(process_snapshot()),
            terminate=_never,
            stderr=stderr,
        )

        assert code == elevation_helper.EXIT_FAILED
        assert existing.read_text(encoding="utf-8") == "someone else's"

    def test_main_refuses_a_result_directory_reached_through_a_junction(
        self, tmp_path: Path
    ) -> None:
        # The unelevated user could point their data directory anywhere, e.g. System32.
        target = tmp_path / "protected"
        target.mkdir()
        link = tmp_path / "elevated"
        _winapi.CreateJunction(str(target), str(link))
        stderr = io.StringIO()

        code = elevation_helper.main(
            encode_request(REQUEST, link / RESULT_NAME),
            process_reader=FakeProcessReader(process_snapshot()),
            terminate=_never,
            stderr=stderr,
        )

        assert code == elevation_helper.EXIT_FAILED
        assert list(target.iterdir()) == []
        assert "through a link" in stderr.getvalue()

    def test_helper_executable_lives_next_to_the_interpreter(self) -> None:
        assert elevation_helper.helper_executable().name == "windows-medic-elevated.exe"


def _never(identity: ProcessIdentity) -> TerminationAttempt:
    raise AssertionError(f"must not terminate {identity}")


class TestLauncher:
    def scripted(
        self, *, writes: ElevatedResult | str | None, launch: Launch
    ) -> tuple[UacElevationLauncher, list[list[str]]]:
        seen: list[list[str]] = []

        def fake_launch(executable: Path, parameters: list[str], timeout: timedelta) -> Launch:
            seen.append([str(executable), *parameters])
            assert timeout == timedelta(seconds=30)
            if writes is not None:
                path = Path(parameters[-1])
                text = writes if isinstance(writes, str) else encode_result(writes)
                path.write_text(text, encoding="utf-8")
            return launch

        launcher = UacElevationLauncher(
            helper=Path("C:/venv/Scripts/windows-medic-elevated.exe"),
            result_dir=self.result_dir,
            timeout=timedelta(seconds=30),
            launch=fake_launch,
        )
        return launcher, seen

    @pytest.fixture(autouse=True)
    def _dirs(self, tmp_path: Path) -> None:
        self.result_dir = tmp_path / "elevated"

    def test_the_helper_result_is_returned_and_the_file_removed(self) -> None:
        completed = ElevatedResult(
            ElevatedOutcome.COMPLETED, TerminationAttempt(TerminationOutcome.SIGNALLED)
        )
        launcher, seen = self.scripted(writes=completed, launch=Launch(LaunchOutcome.EXITED, 0))

        result = launcher.run(REQUEST)

        assert result == completed
        assert seen[0][0].endswith("windows-medic-elevated.exe")
        assert seen[0][1] == "windows.dwm.terminate"
        assert seen[0][-1].endswith(".json")
        assert list(self.result_dir.iterdir()) == []

    def test_a_cancelled_prompt_is_declined(self) -> None:
        launcher, _ = self.scripted(
            writes=None,
            launch=Launch(LaunchOutcome.DECLINED, detail="the UAC prompt was cancelled"),
        )

        result = launcher.run(REQUEST)

        assert result == ElevatedResult(
            ElevatedOutcome.DECLINED, detail="the UAC prompt was cancelled"
        )

    def test_a_slow_helper_times_out(self) -> None:
        launcher, _ = self.scripted(
            writes=None, launch=Launch(LaunchOutcome.TIMED_OUT, detail="slow")
        )

        assert launcher.run(REQUEST).outcome is ElevatedOutcome.TIMED_OUT

    def test_a_launch_failure_is_a_failure(self) -> None:
        launcher, _ = self.scripted(writes=None, launch=Launch(LaunchOutcome.FAILED, detail="no"))

        result = launcher.run(REQUEST)

        assert result.outcome is ElevatedOutcome.FAILED
        assert result.detail == "no"

    def test_a_helper_that_leaves_no_result_is_a_failure(self) -> None:
        launcher, _ = self.scripted(writes=None, launch=Launch(LaunchOutcome.EXITED, 1))

        result = launcher.run(REQUEST)

        assert result.outcome is ElevatedOutcome.FAILED
        assert result.detail == "the helper exited with code 1 and left no result"

    def test_an_unreadable_result_is_a_failure(self) -> None:
        launcher, _ = self.scripted(writes="garbage", launch=Launch(LaunchOutcome.EXITED, 0))

        result = launcher.run(REQUEST)

        assert result.outcome is ElevatedOutcome.FAILED
        assert result.detail == "the helper left an unreadable result"

    def test_a_result_dir_that_cannot_be_created_is_a_failure(self, tmp_path: Path) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        launcher = UacElevationLauncher(
            helper=Path("C:/x.exe"),
            result_dir=blocker / "sub",
            timeout=timedelta(seconds=1),
            launch=lambda *_: Launch(LaunchOutcome.EXITED, 0),
        )

        result = launcher.run(REQUEST)

        assert result.outcome is ElevatedOutcome.FAILED
        assert result.detail is not None
        assert result.detail.startswith("cannot prepare result dir")


class FakeShell32:
    def __init__(self, *, error: int | None = None, handle: int = 0x77) -> None:
        self.error = error
        self.handle = handle
        self.seen: list[tuple[str, str, str]] = []

    def ShellExecuteExW(self, info: "ctypes._Pointer[ShellExecuteInfoW]") -> int:  # noqa: N802
        contents = info.contents
        self.seen.append((contents.lpVerb, contents.lpFile, contents.lpParameters))
        if self.error is not None:
            ctypes.set_last_error(self.error)
            return 0
        contents.hProcess = self.handle
        return 1


class FakeKernel32:
    def __init__(self, *, wait: int = WAIT_OBJECT_0, exit_code: int = 0) -> None:
        self.wait = wait
        self.exit_code = exit_code
        self.closed: list[int] = []

    def WaitForSingleObject(self, handle: int, milliseconds: int) -> int:  # noqa: N802
        assert milliseconds == 30_000
        return self.wait

    def GetExitCodeProcess(self, handle: int, code: "ctypes._Pointer[wintypes.DWORD]") -> int:  # noqa: N802
        code.contents.value = self.exit_code
        return 1

    def CloseHandle(self, handle: int) -> int:  # noqa: N802
        self.closed.append(handle)
        return 1


class TestLaunchAsAdministrator:
    def test_runs_the_helper_with_the_runas_verb_and_quoted_parameters(self) -> None:
        shell32, kernel32 = FakeShell32(), FakeKernel32(exit_code=2)

        launch = launch_as_administrator(
            Path("C:/Scripts/windows-medic-elevated.exe"),
            ["windows.dwm.terminate", "--result", "C:/My Data/r.json"],
            timedelta(seconds=30),
            shell32=shell32,
            kernel32=kernel32,
        )

        assert launch == Launch(LaunchOutcome.EXITED, exit_code=2)
        assert shell32.seen == [
            (
                "runas",
                "C:\\Scripts\\windows-medic-elevated.exe",
                'windows.dwm.terminate --result "C:/My Data/r.json"',
            )
        ]
        assert kernel32.closed == [0x77]

    def test_a_cancelled_uac_prompt_is_declined(self) -> None:
        launch = launch_as_administrator(
            Path("C:/x.exe"),
            [],
            timedelta(seconds=30),
            shell32=FakeShell32(error=ERROR_CANCELLED),
            kernel32=FakeKernel32(),
        )

        assert launch.outcome is LaunchOutcome.DECLINED

    def test_other_shell_execute_errors_fail(self) -> None:
        launch = launch_as_administrator(
            Path("C:/x.exe"),
            [],
            timedelta(seconds=30),
            shell32=FakeShell32(error=2),
            kernel32=FakeKernel32(),
        )

        assert launch.outcome is LaunchOutcome.FAILED
        assert launch.detail is not None
        assert launch.detail.startswith("ShellExecuteEx: [WinError 2]")

    def test_a_missing_handle_fails(self) -> None:
        launch = launch_as_administrator(
            Path("C:/x.exe"),
            [],
            timedelta(seconds=30),
            shell32=FakeShell32(handle=0),
            kernel32=FakeKernel32(),
        )

        assert launch.outcome is LaunchOutcome.FAILED

    @pytest.mark.parametrize(
        ("wait", "expected"),
        [(WAIT_TIMEOUT, LaunchOutcome.TIMED_OUT), (0xFFFFFFFF, LaunchOutcome.FAILED)],
    )
    def test_waiting_outcomes(self, wait: int, expected: LaunchOutcome) -> None:
        kernel32 = FakeKernel32(wait=wait)

        launch = launch_as_administrator(
            Path("C:/x.exe"), [], timedelta(seconds=30), shell32=FakeShell32(), kernel32=kernel32
        )

        assert launch.outcome is expected
        assert kernel32.closed == [0x77]


def test_a_request_needs_a_non_negative_session() -> None:
    with pytest.raises(ValueError, match="session"):
        ElevatedRequest(ElevatedRecipe.WINDOWS_DWM_TERMINATE, identity(300), -1)


def test_a_failing_exit_code_query_fails_the_launch() -> None:
    class NoExitCode(FakeKernel32):
        def GetExitCodeProcess(  # noqa: N802
            self, handle: int, code: "ctypes._Pointer[wintypes.DWORD]"
        ) -> int:
            return 0

    launch = launch_as_administrator(
        Path("C:/x.exe"), [], timedelta(seconds=30), shell32=FakeShell32(), kernel32=NoExitCode()
    )

    assert launch == Launch(LaunchOutcome.FAILED, detail="GetExitCodeProcess failed")
