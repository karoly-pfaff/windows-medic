"""``windows-medic`` command-line entry point.

Commands are thin: parse arguments, obtain the composed container, invoke one use case,
render its typed result. Expected failures become messages and exit codes, never tracebacks.
"""

import argparse
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Protocol, TextIO

import windows_medic
from windows_medic.application.use_cases.list_recent_incidents import DEFAULT_LIMIT
from windows_medic.application.use_cases.list_recent_repairs import (
    DEFAULT_LIMIT as DEFAULT_REPAIR_LIMIT,
)
from windows_medic.domain.errors import WindowsMedicError
from windows_medic.domain.models.component import WindowsComponent
from windows_medic.domain.models.network import MAX_PORT, MIN_PORT
from windows_medic.domain.models.process import MAX_PID
from windows_medic.domain.models.repair import RepairRecord, RepairScope, RepairStatus
from windows_medic_cli import operations
from windows_medic_cli.render import (
    render_diagnosis,
    render_health,
    render_incidents,
    render_inspection,
    render_port_inspection,
    render_repair,
    render_repairs,
)
from windows_medic_root.container import (
    EXIT_CONFIGURATION_ERROR,
    Container,
    try_compose,
    utf8_text,
)

PROGRAM = "windows-medic"
EXIT_FAILURE = 1
EXIT_USAGE = 2


class Composer(Protocol):
    """Shape of :func:`windows_medic_root.container.try_compose` (injectable in tests)."""

    def __call__(
        self, program: str, *, environ: Mapping[str, str], log_stream: TextIO, error_stream: TextIO
    ) -> Container | None: ...


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    compose: Composer = try_compose,
) -> int:
    """Run the CLI and return the process exit code."""
    environ = os.environ if environ is None else environ
    stdout = utf8_text(sys.stdout if stdout is None else stdout)
    stderr = utf8_text(sys.stderr if stderr is None else stderr)

    parser = _build_parser()
    arguments = parser.parse_args(argv)

    if arguments.version:
        stdout.write(f"{PROGRAM} {windows_medic.__version__}\n")
        return 0

    container = compose(PROGRAM, environ=environ, log_stream=stderr, error_stream=stderr)
    if container is None:
        return EXIT_CONFIGURATION_ERROR

    try:
        return _dispatch(container, arguments, stdout, stderr)
    finally:
        container.close()


def _dispatch(
    container: Container, arguments: argparse.Namespace, stdout: TextIO, stderr: TextIO
) -> int:
    a = arguments
    commands: dict[str, Callable[[], int]] = {
        "health": lambda: _run_health(container, stdout, stderr),
        "inspect": lambda: _run_inspect(container, a.pid, a.create_time, stdout, stderr),
        "port": lambda: _run_port(container, a.port, stdout, stderr),
        "incidents": lambda: _run_incidents(container, a.limit, stdout, stderr),
        "diagnose": lambda: _run_diagnose(container, a.since_minutes, stdout, stderr),
        "terminate": lambda: _run_terminate(
            container,
            pid=a.pid,
            create_time=a.create_time,
            scope=RepairScope.TREE if a.tree else RepairScope.PROCESS,
            stdout=stdout,
            stderr=stderr,
        ),
        "clear-port": lambda: _run_clear_port(container, a.port, stdout, stderr),
        "repairs": lambda: _run_repairs(container, a.limit, stdout, stderr),
        "restart-component": lambda: _run_restart_component(container, a.component, stdout, stderr),
        **operations.commands_for(container, a, stdout, stderr),
    }
    command = commands.get(a.command)
    if command is None:
        operations.write_overview(container, stdout)
        return 0
    return command()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM, description="Local Windows diagnostics and recovery for Claude Code."
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser(
        "health",
        help="measure current CPU, memory, commit, disk I/O and top contributors",
        description=(
            "Take two snapshots across the configured measurement window and report "
            "system health with bounded, deterministically ranked contributors."
        ),
    )
    inspect = commands.add_parser(
        "inspect",
        help="describe one process: identity, ancestry, descendants, protection, risk",
        description=(
            "Look up a process by PID (optionally insisting on its exact create time) and "
            "report its place in the process tree, protection level and risk markers."
        ),
    )
    inspect.add_argument("pid", type=_pid, help="process id")
    inspect.add_argument(
        "--create-time",
        type=_aware_datetime,
        default=None,
        metavar="ISO8601",
        help="exact creation time (timezone-aware ISO 8601); rejects a reused PID",
    )
    port = commands.add_parser(
        "port",
        help="find out what listens on a TCP port, by exact process identity",
        description=(
            "Resolve the listeners on a TCP port to exact process identities with tree, "
            "protection and risk context, and report whether a clear-port plan is eligible."
        ),
    )
    port.add_argument("port", type=_port, help="TCP port (1-65535)")
    incidents = commands.add_parser(
        "incidents",
        help="list recent pressure incidents recorded by the agent, newest first",
        description="List persisted incidents (bounded, newest first).",
    )
    incidents.add_argument(
        "--limit",
        type=_positive_int,
        default=DEFAULT_LIMIT,
        metavar="N",
        help=f"maximum number of incidents to show (default {DEFAULT_LIMIT})",
    )
    diagnose = commands.add_parser(
        "diagnose",
        help="explain why the machine is (or recently was) slow, from evidence",
        description=(
            "Combine the incidents recorded by the agent inside the lookback window with a "
            "fresh measurement and Windows' hung-window verdicts into ranked findings, each "
            "with its evidence, confidence rationale and candidate repairs (nothing is executed)."
        ),
    )
    diagnose.add_argument(
        "--since-minutes",
        type=_positive_int,
        default=None,
        metavar="N",
        help="lookback window in minutes (default and maximum are configured)",
    )
    terminate = commands.add_parser(
        "terminate",
        help="terminate one exact process identity (or its tree); audited and verified",
        description=(
            "Terminate the process identified by PID and exact create time after "
            "revalidating it, checking protection policy and recording the intent; the "
            "result is verified by observation and audited. Never automatic."
        ),
    )
    terminate.add_argument("pid", type=_pid, help="process id")
    terminate.add_argument(
        "--create-time",
        type=_aware_datetime,
        required=True,
        metavar="ISO8601",
        help="exact creation time (timezone-aware ISO 8601); a PID alone is never enough",
    )
    terminate.add_argument(
        "--tree", action="store_true", help="also terminate its descendants, parents first"
    )
    clear_port = commands.add_parser(
        "clear-port",
        help="terminate the confirmed owner(s) of a TCP port and verify it is free",
        description=(
            "Resolve the listener(s) on the port to exact identities immediately before "
            "acting, refuse protected or unresolved owners, terminate the rest and verify "
            "that nothing listens afterwards. Audited."
        ),
    )
    clear_port.add_argument("port", type=_port, help="TCP port (1-65535)")
    restart = commands.add_parser(
        "restart-component",
        help="restart Explorer (or, when enabled, DWM) for this session; audited and verified",
        description=(
            "Terminate the session's shell (explorer) or compositor (dwm) instance by exact "
            "identity and verify that a healthy replacement exists. Explorer is started "
            "from its system location if Windows does not recreate it; DWM is only ever "
            "recreated by Windows, needs elevation (UAC) and requires "
            "[repairs] high_risk_repairs_enabled = true."
        ),
    )
    restart.add_argument(
        "component",
        type=WindowsComponent,
        choices=list(WindowsComponent),
        help="explorer or dwm",
    )
    repairs = commands.add_parser(
        "repairs",
        help="list recent repair attempts (audit), newest first",
        description="List the repair audit (bounded, newest first).",
    )
    repairs.add_argument(
        "--limit",
        type=_positive_int,
        default=DEFAULT_REPAIR_LIMIT,
        metavar="N",
        help=f"maximum number of repairs to show (default {DEFAULT_REPAIR_LIMIT})",
    )
    operations.add_parsers(commands)
    return parser


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a whole number: {value!r}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _port(value: str) -> int:
    port = int(value)
    if not MIN_PORT <= port <= MAX_PORT:
        raise argparse.ArgumentTypeError(f"port must be between {MIN_PORT} and {MAX_PORT}")
    return port


def _pid(value: str) -> int:
    pid = int(value)
    if not 0 <= pid <= MAX_PID:
        raise argparse.ArgumentTypeError(f"pid must be between 0 and {MAX_PID}")
    return pid


def _aware_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an ISO 8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("create time must include a timezone offset")
    return parsed


def _run_health(container: Container, stdout: TextIO, stderr: TextIO) -> int:
    try:
        health = container.get_system_health.execute()
    except WindowsMedicError as exc:
        stderr.write(f"{PROGRAM}: {exc}\n")
        return EXIT_FAILURE
    stdout.write(render_health(health))
    return 0


def _run_inspect(
    container: Container,
    pid: int,
    create_time: datetime | None,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    try:
        inspection = container.inspect_process.execute(pid, create_time)
    except WindowsMedicError as exc:
        stderr.write(f"{PROGRAM}: {exc}\n")
        return EXIT_FAILURE
    stdout.write(render_inspection(inspection))
    return 0


def _run_port(container: Container, port: int, stdout: TextIO, stderr: TextIO) -> int:
    try:
        inspection = container.inspect_port.execute(port)
    except WindowsMedicError as exc:
        stderr.write(f"{PROGRAM}: {exc}\n")
        return EXIT_FAILURE
    stdout.write(render_port_inspection(inspection))
    return 0


def _run_incidents(container: Container, limit: int, stdout: TextIO, stderr: TextIO) -> int:
    try:
        summaries = container.list_recent_incidents.execute(limit)
    except WindowsMedicError as exc:
        stderr.write(f"{PROGRAM}: {exc}\n")
        return EXIT_FAILURE
    stdout.write(render_incidents(summaries))
    return 0


def _run_diagnose(
    container: Container, since_minutes: int | None, stdout: TextIO, stderr: TextIO
) -> int:
    use_case = container.diagnose_slowdown
    lookback = None if since_minutes is None else timedelta(minutes=since_minutes)
    if lookback is not None and lookback > use_case.limits.max_lookback:
        maximum = int(use_case.limits.max_lookback.total_seconds() // 60)
        stderr.write(f"{PROGRAM}: --since-minutes must be between 1 and {maximum}\n")
        return EXIT_USAGE
    try:
        diagnosis = use_case.execute(lookback)
    except WindowsMedicError as exc:
        stderr.write(f"{PROGRAM}: {exc}\n")
        return EXIT_FAILURE
    stdout.write(render_diagnosis(diagnosis))
    return 0


def _run_terminate(
    container: Container,
    *,
    pid: int,
    create_time: datetime,
    scope: RepairScope,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    try:
        record = container.terminate_process.execute(pid, create_time, scope)
    except WindowsMedicError as exc:
        stderr.write(f"{PROGRAM}: {exc}\n")
        return EXIT_FAILURE
    return _report_repair(record, stdout)


def _run_clear_port(container: Container, port: int, stdout: TextIO, stderr: TextIO) -> int:
    try:
        record = container.clear_port.execute(port)
    except WindowsMedicError as exc:
        stderr.write(f"{PROGRAM}: {exc}\n")
        return EXIT_FAILURE
    return _report_repair(record, stdout)


def _run_restart_component(
    container: Container, component: WindowsComponent, stdout: TextIO, stderr: TextIO
) -> int:
    try:
        record = container.restart_windows_component.execute(component)
    except WindowsMedicError as exc:
        stderr.write(f"{PROGRAM}: {exc}\n")
        return EXIT_FAILURE
    return _report_repair(record, stdout)


def _report_repair(record: RepairRecord, stdout: TextIO) -> int:
    stdout.write(render_repair(record))
    return 0 if record.status is RepairStatus.SUCCEEDED else EXIT_FAILURE


def _run_repairs(container: Container, limit: int, stdout: TextIO, stderr: TextIO) -> int:
    try:
        records = container.list_recent_repairs.execute(limit)
    except WindowsMedicError as exc:
        stderr.write(f"{PROGRAM}: {exc}\n")
        return EXIT_FAILURE
    stdout.write(render_repairs(records))
    return 0
