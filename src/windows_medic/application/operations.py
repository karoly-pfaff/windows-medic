"""Facts the operational use cases (doctor, status, install) share.

Where the files live and which executables exist are decided once at the composition
root and handed in as plain values; the use cases only reason about them.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.policies.naming import basename, candidate_names

AGENT_LOG_NAME = "windows-medic-agent.log"
# Result files of the elevated helper: elevated-<uuid>.json in the elevated directory.
ELEVATED_RESULT_PREFIX = "elevated-"
# SQLite companions of the database file (WAL mode, rollback journal).
DATABASE_COMPANION_SUFFIXES = ("-wal", "-shm", "-journal")


@dataclass(frozen=True, slots=True)
class Locations:
    """The user's data layout. ``config_file`` is the effective path even when absent."""

    data_dir: Path
    config_file: Path
    config_present: bool
    database: Path
    log_dir: Path
    log_file: Path
    elevated_dir: Path


@dataclass(frozen=True, slots=True)
class Executables:
    """Console scripts installed next to the interpreter."""

    cli: Path
    agent: Path
    agent_gui: Path
    mcp_server: Path
    elevated_helper: Path

    def all(self) -> tuple[Path, ...]:
        return (self.cli, self.agent, self.agent_gui, self.mcp_server, self.elevated_helper)


@dataclass(frozen=True, slots=True)
class Runtime:
    package_version: str
    python_version: str
    python_executable: Path


def agent_command(executables: Executables, locations: Locations) -> tuple[str, ...]:
    """The exact command the logon task runs: the windowless agent, logging to a file."""
    return (str(executables.agent_gui), "--log-file", str(locations.log_file))


def agent_processes(
    processes: Sequence[ProcessObservation], executables: Executables
) -> tuple[ProcessObservation, ...]:
    """Processes that are a Windows Medic agent: the launcher, or a Python interpreter whose
    script (its first argument) is the launcher. A program that merely mentions the launcher
    in its arguments (an editor that opened it) is not an agent."""
    launchers = {basename(str(executables.agent)), basename(str(executables.agent_gui))}
    found: list[ProcessObservation] = []
    for observation in processes:
        names = candidate_names(observation)
        interpreter = any(_is_python(name) for name in names)
        runs_launcher = (
            interpreter
            and available(observation.command_line)
            and len(observation.command_line) >= 2  # noqa: PLR2004 - interpreter, script
            and basename(observation.command_line[1]) in launchers
        )
        if names & launchers or runs_launcher:
            found.append(observation)
    return tuple(found)


def _is_python(name: str) -> bool:
    # python.exe, pythonw.exe, python3.exe, python3.13.exe
    return name.startswith("python") and name.endswith(".exe")
