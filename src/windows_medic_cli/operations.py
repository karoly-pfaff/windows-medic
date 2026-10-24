"""Operational commands: doctor, status, install/uninstall, config, mcp-config.

Same shape as the diagnostic commands: parse, invoke one use case, render. The install
and uninstall commands are the only ones here that change anything, and they say what
they changed.
"""

import argparse
from collections.abc import Callable
from typing import TextIO

from windows_medic.domain.errors import WindowsMedicError
from windows_medic_cli.render import (
    render_config_check,
    render_doctor,
    render_install,
    render_mcp_config,
    render_overview,
    render_status,
    render_uninstall,
)
from windows_medic_root.container import Container

EXIT_FAILURE = 1

type Subparsers = argparse._SubParsersAction[argparse.ArgumentParser]


def add_parsers(commands: Subparsers) -> None:
    commands.add_parser(
        "doctor",
        help="verify the installation: runtime, config, data directory, database, "
        "executables, logon task, agent",
        description=(
            "Check every prerequisite of a working installation and report each with a "
            "status and what to do about it. Changes nothing. Exit code 1 when a check fails."
        ),
    )
    commands.add_parser(
        "status",
        help="where the files are, whether the agent runs, and the latest records",
        description=(
            "Report the data layout, the agent and logon-task state and the most recent "
            "incident and repair. Changes nothing."
        ),
    )
    install = commands.add_parser(
        "install-agent",
        help="create the data directory, write defaults, register the logon task, start",
        description=(
            "Create %LOCALAPPDATA%\\WindowsMedic (config, logs, elevated), write config.toml "
            "when absent, register a Task Scheduler logon task that runs the agent "
            "unelevated as you, and start it now. Idempotent; no administrator rights."
        ),
    )
    install.add_argument(
        "--no-start", action="store_true", help="register only; the agent starts at next logon"
    )
    uninstall = commands.add_parser(
        "uninstall-agent",
        help="remove the logon task; keep your data unless --purge-data",
        description=(
            "Remove the logon task. With --stop, terminate running agent processes (by exact "
            "identity) and wait for them to exit. With --purge-data, delete the data "
            "directory (incidents, repair audit, logs, config) once no agent runs."
        ),
    )
    uninstall.add_argument("--stop", action="store_true", help="also stop running agents")
    uninstall.add_argument(
        "--purge-data",
        action="store_true",
        help="also delete the data directory (evidence and configuration)",
    )
    config = commands.add_parser(
        "config",
        help="write the default config.toml, or show the configuration in force",
        description="Configuration file helpers.",
    )
    config_commands = config.add_subparsers(dest="config_command", required=True)
    init = config_commands.add_parser(
        "init",
        help="write config.toml with every key commented at its default",
        description="Write the documented defaults to the data directory for editing.",
    )
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    config_commands.add_parser(
        "check",
        help="validate the configuration and print the values in force",
        description=(
            "The configuration was loaded and validated to get here; print where it came "
            "from and every effective value."
        ),
    )
    commands.add_parser(
        "mcp-config",
        help="print the Claude Code .mcp.json snippet for this installation",
        description="Print the MCP server registration (stdio) with the absolute path.",
    )


def commands_for(
    container: Container, a: argparse.Namespace, stdout: TextIO, stderr: TextIO
) -> dict[str, Callable[[], int]]:
    return {
        "doctor": lambda: _run_doctor(container, stdout),
        "status": lambda: _run_status(container, stdout, stderr),
        "install-agent": lambda: _run_install(
            container, start_now=not a.no_start, out=stdout, err=stderr
        ),
        "uninstall-agent": lambda: _run_uninstall(
            container, stop=a.stop, purge_data=a.purge_data, out=stdout, err=stderr
        ),
        "config": lambda: _run_config(container, a, stdout, stderr),
        "mcp-config": lambda: _run_mcp_config(container, stdout),
    }


def write_overview(container: Container, stdout: TextIO) -> None:
    """Bare ``windows-medic``: version, locations and the command list; probes nothing."""
    stdout.write(render_overview(container.runtime, container.locations, container.executables))


def _run_doctor(container: Container, stdout: TextIO) -> int:
    report = container.run_doctor.execute()
    stdout.write(render_doctor(report))
    return 0 if report.healthy else EXIT_FAILURE


def _run_status(container: Container, stdout: TextIO, stderr: TextIO) -> int:
    try:
        report = container.show_status.execute()
    except WindowsMedicError as exc:
        stderr.write(f"windows-medic: {exc}\n")
        return EXIT_FAILURE
    stdout.write(render_status(report))
    return 0


def _run_install(container: Container, *, start_now: bool, out: TextIO, err: TextIO) -> int:
    try:
        report = container.install_agent.execute(start_now=start_now)
    except WindowsMedicError as exc:
        err.write(f"windows-medic: {exc}\n")
        return EXIT_FAILURE
    out.write(render_install(report, container.locations))
    return 0


def _run_uninstall(
    container: Container, *, stop: bool, purge_data: bool, out: TextIO, err: TextIO
) -> int:
    try:
        report = container.uninstall_agent.execute(stop=stop, purge_data=purge_data)
    except WindowsMedicError as exc:
        err.write(f"windows-medic: {exc}\n")
        return EXIT_FAILURE
    out.write(render_uninstall(report, container.locations))
    return EXIT_FAILURE if report.survivors else 0


def _run_config(container: Container, a: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    if a.config_command == "init":
        try:
            written = container.init_config.execute(force=a.force)
        except WindowsMedicError as exc:
            stderr.write(f"windows-medic: {exc}\n")
            return EXIT_FAILURE
        stdout.write(f"Configuration written: {written}\n")
        return 0
    stdout.write(render_config_check(container.locations, container.describe_config()))
    return 0


def _run_mcp_config(container: Container, stdout: TextIO) -> int:
    stdout.write(render_mcp_config(container.executables))
    return 0
