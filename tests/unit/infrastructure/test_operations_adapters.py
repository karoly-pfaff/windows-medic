"""Operational adapters: Task Scheduler registry, named-mutex guard, workspace, config."""

import ctypes
import io
import json
import logging
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from windows_medic.application.ports.startup_registry import Registration
from windows_medic.domain.errors import StartupRegistrationError, WorkspaceError
from windows_medic.infrastructure.config.default_config import (
    render_default_config,
    render_effective_config,
)
from windows_medic.infrastructure.config.settings import LogLevel, load_settings
from windows_medic.infrastructure.filesystem.local_workspace import LocalWorkspace
from windows_medic.infrastructure.observability.structured_logging import (
    close_file_logging,
    configure_file_logging,
    configure_logging,
)
from windows_medic.infrastructure.windows.single_instance import (
    ERROR_ALREADY_EXISTS,
    NamedMutexGuard,
    mutex_name,
)
from windows_medic.infrastructure.windows.task_scheduler import (
    CommandResult,
    SchtasksStartupRegistry,
    parse_task_command,
    task_definition,
)

SCHTASKS = Path("C:/Windows/System32/schtasks.exe")
COMMAND = ["C:/venv/Scripts/windows-medic-agentw.exe", "--log-file", "C:/Data Dir/logs/a.log"]


# `schtasks /Query /FO CSV /NH`: one quoted row per task, the full path first.
LISTING_WITHOUT_OURS = (
    '"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag","N/A","Ready"\r\n'
    '"\\WindowsMedicOther\\Agent","N/A","Ready"\r\n'
)
LISTED_OURS = '"\\WindowsMedic\\Agent","N/A","Ready"\r\n'


class FakeRunner:
    def __init__(self, *results: CommandResult) -> None:
        self._results = list(results)
        self.calls: list[list[str]] = []
        self.xml_seen: list[str] = []

    def __call__(self, command: list[str]) -> CommandResult:
        self.calls.append(command)
        if "/XML" in command and "/Create" in command:
            self.xml_seen.append(Path(command[-1]).read_text(encoding="utf-16"))
        return self._results.pop(0)


class TestTaskScheduler:
    def test_register_creates_a_least_privilege_logon_task_from_xml(self, tmp_path: Path) -> None:
        runner = FakeRunner(CommandResult(0, "SUCCESS", ""))
        registry = SchtasksStartupRegistry(
            schtasks=SCHTASKS, user="DESKTOP\\dev", run=runner, scratch_dir=tmp_path
        )

        registry.register(COMMAND)

        [call] = runner.calls
        assert call[:5] == [str(SCHTASKS), "/Create", "/F", "/TN", "WindowsMedic\\Agent"]
        assert call[5] == "/XML"
        [xml] = runner.xml_seen
        assert "<RunLevel>LeastPrivilege</RunLevel>" in xml
        assert "<LogonType>InteractiveToken</LogonType>" in xml
        assert "<UserId>DESKTOP\\dev</UserId>" in xml
        assert "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>" in xml
        assert "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" in xml
        assert "<Command>C:/venv/Scripts/windows-medic-agentw.exe</Command>" in xml
        assert '<Arguments>--log-file "C:/Data Dir/logs/a.log"</Arguments>' in xml
        assert not list(tmp_path.iterdir())  # the XML file was temporary

    def test_register_failure_carries_the_schtasks_message(self, tmp_path: Path) -> None:
        runner = FakeRunner(CommandResult(1, "", "ERROR: Access is denied.\n"))
        registry = SchtasksStartupRegistry(
            schtasks=SCHTASKS, user="u", run=runner, scratch_dir=tmp_path
        )

        with pytest.raises(StartupRegistrationError, match="Access is denied"):
            registry.register(COMMAND)

    def test_state_reads_the_command_back_from_the_task_xml(self) -> None:
        runner = FakeRunner(CommandResult(0, task_definition(COMMAND, user="u"), ""))
        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="u", run=runner)

        state = registry.state()

        assert state.registration is Registration.REGISTERED
        assert state.command == (
            'C:/venv/Scripts/windows-medic-agentw.exe --log-file "C:/Data Dir/logs/a.log"'
        )
        assert runner.calls == [[str(SCHTASKS), "/Query", "/TN", "WindowsMedic\\Agent", "/XML"]]

    def test_an_absent_task_is_not_registered_once_the_task_list_confirms_it(self) -> None:
        runner = FakeRunner(
            CommandResult(1, "", "HIBA: A rendszer nem találja a megadott fájlt."),
            CommandResult(0, LISTING_WITHOUT_OURS, ""),
        )
        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="u", run=runner)

        state = registry.state()

        assert state.registration is Registration.NOT_REGISTERED
        assert state.detail == "HIBA: A rendszer nem találja a megadott fájlt."
        assert runner.calls[1] == [str(SCHTASKS), "/Query", "/FO", "CSV", "/NH"]

    def test_a_failing_query_of_a_listed_task_is_unknown_not_absent(self) -> None:
        # The task exists but its definition cannot be read (e.g. access denied).
        runner = FakeRunner(
            CommandResult(1, "", "ERROR: Access is denied."),
            CommandResult(0, LISTING_WITHOUT_OURS + LISTED_OURS, ""),
        )
        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="u", run=runner)

        state = registry.state()

        assert state.registration is Registration.UNKNOWN
        assert state.detail == "ERROR: Access is denied."

    def test_when_even_the_task_list_fails_the_state_is_unknown(self) -> None:
        runner = FakeRunner(
            CommandResult(1, "", "ERROR: The RPC server is unavailable."),
            CommandResult(1, "", "ERROR: The RPC server is unavailable."),
        )
        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="u", run=runner)

        assert registry.state().registration is Registration.UNKNOWN

    def test_when_the_task_list_cannot_even_run_the_state_is_unknown(self) -> None:
        answers = iter([CommandResult(1, "", "ERROR: x")])

        def runner(command: list[str]) -> CommandResult:
            if "/FO" in command:
                raise subprocess.TimeoutExpired(command, 10)
            return next(answers)

        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="u", run=runner)

        assert registry.state().registration is Registration.UNKNOWN

    def test_a_task_without_an_exec_action_is_unknown(self) -> None:
        runner = FakeRunner(CommandResult(0, "<Task><Actions/></Task>", ""))
        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="u", run=runner)

        assert registry.state().registration is Registration.UNKNOWN

    def test_unregister_reports_whether_a_task_was_removed(self) -> None:
        removed = SchtasksStartupRegistry(
            schtasks=SCHTASKS, user="u", run=FakeRunner(CommandResult(0, "SUCCESS", ""))
        )
        absent = SchtasksStartupRegistry(
            schtasks=SCHTASKS,
            user="u",
            run=FakeRunner(
                CommandResult(1, "", "ERROR: not found"),
                CommandResult(1, "", "gone"),
                CommandResult(0, LISTING_WITHOUT_OURS, ""),
            ),
        )
        broken = SchtasksStartupRegistry(
            schtasks=SCHTASKS,
            user="u",
            run=FakeRunner(
                CommandResult(1, "", "ERROR: Access is denied."),
                CommandResult(0, task_definition(COMMAND, user="u"), ""),
            ),
        )

        assert removed.unregister() is True
        assert absent.unregister() is False
        with pytest.raises(StartupRegistrationError, match="Access is denied"):
            broken.unregister()

    def test_run_now(self) -> None:
        runner = FakeRunner(CommandResult(0, "SUCCESS", ""), CommandResult(1, "", "ERROR: nope"))
        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="u", run=runner)

        registry.run_now()
        with pytest.raises(StartupRegistrationError, match="nope"):
            registry.run_now()

        assert runner.calls[0] == [str(SCHTASKS), "/Run", "/TN", "WindowsMedic\\Agent"]

    def test_task_command_parsing_unescapes_and_tolerates_garbage(self) -> None:
        assert parse_task_command("<Command>a &amp; b</Command><Arguments>--x</Arguments>") == (
            "a & b --x"
        )
        assert parse_task_command("<Command>only</Command>") == "only"
        assert parse_task_command("<Command></Command>") is None
        assert parse_task_command("not xml at all") is None

    def test_exit_code_without_output_is_still_a_message(self) -> None:
        runner = FakeRunner(CommandResult(2, "", ""), CommandResult(0, LISTING_WITHOUT_OURS, ""))
        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="u", run=runner)

        assert registry.state().detail == "schtasks exited with code 2"

    def test_a_missing_or_hanging_schtasks_is_an_error_not_a_traceback(self) -> None:
        def missing(command: list[str]) -> CommandResult:
            raise FileNotFoundError(2, "No such file", command[0])

        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="u", run=missing)

        assert registry.state().registration is Registration.UNKNOWN
        assert "No such file" in (registry.state().detail or "")
        with pytest.raises(StartupRegistrationError, match="No such file"):
            registry.register(COMMAND)
        with pytest.raises(StartupRegistrationError, match="No such file"):
            registry.unregister()
        with pytest.raises(StartupRegistrationError, match="No such file"):
            registry.run_now()

    def test_registering_without_a_known_user_is_refused_before_touching_schtasks(self) -> None:
        runner = FakeRunner()
        registry = SchtasksStartupRegistry(schtasks=SCHTASKS, user="", run=runner)

        with pytest.raises(StartupRegistrationError, match="USERNAME"):
            registry.register(COMMAND)

        assert runner.calls == []


class FakeKernel32:
    def __init__(self, *, already_exists: bool = False, fail: bool = False) -> None:
        self.already_exists = already_exists
        self.fail = fail
        self.created: list[str] = []
        self.closed: list[int] = []

    def CreateMutexW(self, attributes: object, initial_owner: bool, name: str) -> int:  # noqa: N802
        self.created.append(name)
        if self.fail:
            ctypes.set_last_error(5)
            return 0
        ctypes.set_last_error(ERROR_ALREADY_EXISTS if self.already_exists else 0)
        return 0x55

    def CloseHandle(self, handle: int) -> int:  # noqa: N802
        self.closed.append(handle)
        return 1


class TestNamedMutexGuard:
    def test_first_holder_gets_a_lease_and_releases_it_once(self) -> None:
        kernel32 = FakeKernel32()
        guard = NamedMutexGuard(name="Local\\Test", kernel32=kernel32)

        lease = guard.try_acquire()

        assert lease is not None
        assert kernel32.created == ["Local\\Test"]
        lease.release()
        lease.release()
        assert kernel32.closed == [0x55]

    def test_a_second_holder_gets_nothing_and_leaks_no_handle(self) -> None:
        kernel32 = FakeKernel32(already_exists=True)

        assert NamedMutexGuard(kernel32=kernel32).try_acquire() is None
        assert kernel32.closed == [0x55]

    def test_creation_failure_raises(self) -> None:
        with pytest.raises(OSError, match="denied"):
            NamedMutexGuard(kernel32=FakeKernel32(fail=True)).try_acquire()


class TestLocalWorkspace:
    def test_directory_probe_and_sizes(self, tmp_path: Path) -> None:
        workspace = LocalWorkspace()
        target = tmp_path / "data" / "logs"

        workspace.ensure_directory(target)

        assert workspace.probe_writable(target) is None
        assert workspace.probe_writable(tmp_path / "missing") is not None
        assert workspace.exists(target) is True
        assert workspace.size(target / "nothing") is None
        workspace.write_text(target / "a.txt", "hello", overwrite=False)
        assert workspace.size(target / "a.txt") == 5

    def test_write_refuses_to_clobber_unless_forced(self, tmp_path: Path) -> None:
        workspace = LocalWorkspace()
        path = tmp_path / "config.toml"
        workspace.write_text(path, "one", overwrite=False)

        with pytest.raises(WorkspaceError, match="already exists"):
            workspace.write_text(path, "two", overwrite=False)
        workspace.write_text(path, "two", overwrite=True)

        assert path.read_text(encoding="utf-8") == "two"

    def test_files_and_empty_directories_are_removed_idempotently(self, tmp_path: Path) -> None:
        workspace = LocalWorkspace()
        directory = tmp_path / "data"
        (directory / "logs").mkdir(parents=True)
        (directory / "a.log").write_text("x", encoding="utf-8")

        assert workspace.children(directory) == (directory / "a.log", directory / "logs")
        assert workspace.children(tmp_path / "missing") == ()
        workspace.remove_file(directory / "a.log")
        workspace.remove_file(directory / "a.log")
        assert workspace.remove_empty_directory(directory / "logs") is True
        assert workspace.remove_empty_directory(directory) is True
        assert workspace.remove_empty_directory(directory) is True
        assert not directory.exists()

    def test_a_directory_with_contents_is_never_removed(self, tmp_path: Path) -> None:
        workspace = LocalWorkspace()
        (tmp_path / "keep.txt").write_text("precious", encoding="utf-8")

        assert workspace.remove_empty_directory(tmp_path) is False
        assert (tmp_path / "keep.txt").read_text(encoding="utf-8") == "precious"

    def test_filesystem_errors_are_workspace_errors(self, tmp_path: Path) -> None:
        workspace = LocalWorkspace()
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")

        with pytest.raises(WorkspaceError, match="cannot create"):
            workspace.ensure_directory(blocker / "child")
        with pytest.raises(WorkspaceError, match="cannot write"):
            workspace.write_text(blocker / "child" / "c.toml", "x", overwrite=True)
        with pytest.raises(WorkspaceError, match="cannot list"):
            workspace.children(blocker)
        (tmp_path / "dir").mkdir()
        with pytest.raises(WorkspaceError, match="cannot remove"):
            workspace.remove_file(tmp_path / "dir")


class TestDefaultConfig:
    def test_rendered_defaults_cover_every_section_and_round_trip(self, tmp_path: Path) -> None:
        text = render_default_config()

        assert text.startswith("# Windows Medic configuration.")
        for section in ("sampling", "pressure", "history", "repairs", "diagnosis", "logging"):
            assert f"\n[{section}]\n" in text
        assert "# high_risk_repairs_enabled = false" in text
        assert '# claude_markers = ["claude"]' in text
        # Uncommenting a few keys must load exactly as the typed settings expect.
        config = tmp_path / "config.toml"
        config.write_text(
            text.replace("# cpu_percent = 90.0", "cpu_percent = 80.0").replace(
                "# high_risk_repairs_enabled = false", "high_risk_repairs_enabled = true"
            ),
            encoding="utf-8",
        )
        settings = load_settings(
            environ={"WINDOWS_MEDIC_DATA_DIR": str(tmp_path)}, config_path=config
        )
        assert settings.pressure.cpu_percent == 80.0
        assert settings.repairs.high_risk_repairs_enabled is True

    def test_effective_config_shows_the_values_in_force_uncommented(self, tmp_path: Path) -> None:
        settings = load_settings(
            environ={"WINDOWS_MEDIC_DATA_DIR": str(tmp_path), "WINDOWS_MEDIC_LOG_LEVEL": "DEBUG"}
        )

        text = render_effective_config(settings)

        assert text.startswith(f"data_dir = {_toml_path(tmp_path)}\n")
        assert "\n[logging]\n" in text
        assert '\nlevel = "DEBUG"\n' in text
        assert "\ncpu_percent = 90.0\n" in text
        assert "# " not in text


def _toml_path(path: Path) -> str:
    return '"' + str(path).replace("\\", "\\\\") + '"'


@pytest.fixture
def root_logger_state() -> Iterator[None]:
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    yield
    close_file_logging()
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


class TestFileLogging:
    def test_file_logging_writes_bounded_json_lines_next_to_the_stream(
        self, tmp_path: Path, root_logger_state: None
    ) -> None:
        stream = io.StringIO()
        configure_logging(LogLevel.INFO, stream)
        path = tmp_path / "logs" / "agent.log"

        configure_file_logging(LogLevel.INFO, path, max_bytes=64 * 1024, backup_count=1)
        logging.getLogger("windows_medic.probe").info("probe.event")
        close_file_logging()

        lines = path.read_text(encoding="utf-8").splitlines()
        assert [json.loads(line)["event"] for line in lines] == ["probe.event"]
        assert "probe.event" in stream.getvalue()
        logging.getLogger("windows_medic.probe").info("after.close")
        assert "after.close" not in path.read_text(encoding="utf-8")


class TestMutexName:
    def test_is_per_data_directory_and_case_and_separator_insensitive(self) -> None:
        name = mutex_name(Path("C:/Users/dev/AppData/Local/WindowsMedic"))

        assert name.startswith("Local\\WindowsMedic.Agent.")
        assert name == mutex_name(Path("c:\\users\\DEV\\appdata\\local\\windowsmedic"))
        assert name != mutex_name(Path("C:/Users/dev/AppData/Local/WindowsMedic-test"))
