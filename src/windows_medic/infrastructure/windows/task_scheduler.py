""":class:`StartupRegistry` over Windows Task Scheduler (``schtasks.exe``), unelevated.

The task is created from an XML definition (no ``/TR`` length limit, explicit settings):
it runs at the current user's logon, as that user, with least privilege, hidden, without
an execution time limit, and Task Scheduler ignores a second start while one instance
runs. Every call is an argument array to the fixed ``schtasks.exe`` path; nothing is
built from untrusted strings and no shell is involved.
"""

import csv
import re
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape, unescape

from windows_medic.application.ports.startup_registry import Registration, StartupState
from windows_medic.domain.errors import StartupRegistrationError

DEFAULT_TASK_NAME = "WindowsMedic\\Agent"
CREATE_NO_WINDOW = 0x0800_0000
# The task XML is read with two anchored patterns instead of an XML parser: the document
# comes from the local Task Scheduler, only two leaf elements matter, and no entity
# expansion can happen this way.
_COMMAND = re.compile(r"<Command>(.*?)</Command>", re.DOTALL)
_ARGUMENTS = re.compile(r"<Arguments>(.*?)</Arguments>", re.DOTALL)


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


type CommandRunner = Callable[[list[str]], CommandResult]


def run_command(command: list[str]) -> CommandResult:
    """Run an argument array without a shell or a console window."""
    completed = subprocess.run(  # noqa: S603 - fixed executable, argument array, no shell
        command,
        capture_output=True,
        text=True,
        check=False,
        creationflags=CREATE_NO_WINDOW,
        timeout=60,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def task_definition(command: Sequence[str], *, user: str) -> str:
    """Task Scheduler XML for *command* at *user*'s logon, least privilege, hidden."""
    executable, arguments = command[0], subprocess.list2cmdline(list(command[1:]))
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Medic background monitoring agent (unelevated).</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{escape(user)}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(executable)}</Command>
      <Arguments>{escape(arguments)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def parse_task_command(xml_text: str) -> str | None:
    """The ``Command`` plus ``Arguments`` of a task's first Exec action, or ``None``."""
    command = _COMMAND.search(xml_text)
    if command is None or not command.group(1).strip():
        return None
    arguments = _ARGUMENTS.search(xml_text)
    text = unescape(command.group(1).strip())
    if arguments is not None and arguments.group(1).strip():
        text += " " + unescape(arguments.group(1).strip())
    return text


class SchtasksStartupRegistry:
    def __init__(
        self,
        *,
        schtasks: Path,
        user: str,
        task_name: str = DEFAULT_TASK_NAME,
        run: CommandRunner = run_command,
        scratch_dir: Path | None = None,
    ) -> None:
        self._schtasks = str(schtasks)
        self._user = user
        self._task_name = task_name
        self._run = run
        self._scratch_dir = scratch_dir

    @property
    def task_name(self) -> str:
        return self._task_name

    @property
    def user(self) -> str:
        return self._user

    def register(self, command: Sequence[str]) -> None:
        if not self._user:
            raise StartupRegistrationError(
                "cannot register the logon task: the current user is unknown (USERNAME is not set)"
            )
        definition = task_definition(command, user=self._user)
        with tempfile.TemporaryDirectory(dir=self._scratch_dir) as directory:
            path = Path(directory) / "windows-medic-agent.xml"
            path.write_text(definition, encoding="utf-16")
            result = self._invoke(
                "/Create", "/F", "/TN", self._task_name, "/XML", str(path), doing="register"
            )
        if result.returncode != 0:
            raise StartupRegistrationError(
                f"could not register the logon task {self._task_name}: {_message(result)}"
            )

    def unregister(self) -> bool:
        result = self._invoke("/Delete", "/F", "/TN", self._task_name, doing="remove")
        if result.returncode == 0:
            return True
        if self.state().registration is Registration.NOT_REGISTERED:
            return False
        raise StartupRegistrationError(
            f"could not remove the logon task {self._task_name}: {_message(result)}"
        )

    def state(self) -> StartupState:
        try:
            result = self._run([self._schtasks, "/Query", "/TN", self._task_name, "/XML"])
        except (OSError, subprocess.SubprocessError) as exc:
            return StartupState(Registration.UNKNOWN, detail=f"schtasks could not run: {exc}")
        if result.returncode != 0:
            # schtasks exits 1 for every failure with a localized message, so "not found"
            # cannot be told from "access denied"; the full task list decides.
            if self._listed() is False:
                return StartupState(Registration.NOT_REGISTERED, detail=_message(result))
            return StartupState(Registration.UNKNOWN, detail=_message(result))
        command = parse_task_command(result.stdout)
        if command is None:
            return StartupState(Registration.UNKNOWN, detail="task exists but has no Exec action")
        return StartupState(Registration.REGISTERED, command=command)

    def _listed(self) -> bool | None:
        """Whether the task appears in the full task list; ``None`` when it cannot be read."""
        try:
            result = self._run([self._schtasks, "/Query", "/FO", "CSV", "/NH"])
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        wanted = "\\" + self._task_name.strip("\\").lower()
        names = (row[0].lower() for row in csv.reader(result.stdout.splitlines()) if row)
        return wanted in names

    def run_now(self) -> None:
        result = self._invoke("/Run", "/TN", self._task_name, doing="start")
        if result.returncode != 0:
            raise StartupRegistrationError(
                f"could not start the logon task {self._task_name}: {_message(result)}"
            )

    def _invoke(self, *arguments: str, doing: str) -> CommandResult:
        """Run schtasks; a missing or hanging executable is a registration error."""
        try:
            return self._run([self._schtasks, *arguments])
        except (OSError, subprocess.SubprocessError) as exc:
            raise StartupRegistrationError(
                f"could not {doing} the logon task {self._task_name}: schtasks could not run: {exc}"
            ) from exc


def _message(result: CommandResult) -> str:
    text = (result.stderr or result.stdout).strip()
    return text.splitlines()[0] if text else f"schtasks exited with code {result.returncode}"
