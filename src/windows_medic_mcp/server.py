"""``windows-medic-mcp`` stdio MCP server for Claude Code.

Tool handlers are thin: validate boundary input (the SDK validates the JSON schema, the
handlers only parse what the schema cannot express), run exactly one application use
case off the event loop, map the typed result to a bounded response model. Expected
application failures become ``ToolError`` results the model can read; nothing here
decides anything about processes, ports or repairs.

The stdio transport owns stdout. Everything diagnostic (structured logs, configuration
errors) goes to stderr.
"""

import argparse
import atexit
import functools
import logging
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Annotated, Literal, TextIO

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

import windows_medic
from windows_medic.application.observability import log_event
from windows_medic.domain.errors import WindowsMedicError
from windows_medic.domain.models.component import WindowsComponent
from windows_medic.domain.models.network import MAX_PORT, MIN_PORT
from windows_medic.domain.models.process import MAX_PID
from windows_medic.domain.models.repair import RepairScope
from windows_medic_mcp.mapping import (
    to_diagnosis,
    to_health,
    to_incidents,
    to_port_inspection,
    to_process_inspection,
    to_repair,
)
from windows_medic_mcp.schemas import (
    DiagnosisResponse,
    HealthResponse,
    IncidentListResponse,
    PortInspectionResponse,
    ProcessInspectionResponse,
    RepairResponse,
)
from windows_medic_root.container import (
    EXIT_CONFIGURATION_ERROR,
    Container,
    try_compose,
    utf8_text,
)

PROGRAM = "windows-medic-mcp"
READ_TOOLS = (
    "get_system_health",
    "diagnose_slowdown",
    "inspect_process",
    "inspect_port",
    "list_recent_incidents",
)
MUTATION_TOOLS = ("terminate_process", "clear_port", "restart_windows_component")

_READ = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
_MUTATION = ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
)
_logger = logging.getLogger(__name__)

type Pid = Annotated[int, Field(ge=0, le=MAX_PID, description="process id")]
type Port = Annotated[int, Field(ge=MIN_PORT, le=MAX_PORT, description="TCP port")]
type CreateTime = Annotated[
    str,
    Field(
        description=(
            "exact process creation time as an ISO 8601 timestamp with timezone offset, as "
            "reported by inspect_process/diagnose_slowdown; a PID alone never identifies a process"
        )
    ),
]


def create_server(container: Container) -> MCPServer:
    """Build the server with every v1 tool bound to the composed container."""
    settings = container.settings
    server = MCPServer(
        name="windows-medic",
        version=windows_medic.__version__,
        instructions=(
            "Windows Medic diagnoses and repairs a local Windows workstation from captured "
            "evidence. Read tools never change anything. Mutation tools (terminate_process, "
            "clear_port, restart_windows_component) act on exact process identities "
            "(pid + create_time), refuse protected targets, verify their postcondition and "
            "return a structured before/after record; they never run automatically."
        ),
    )
    max_lookback = settings.diagnosis.max_lookback_minutes
    default_lookback = settings.diagnosis.default_lookback_minutes
    max_incidents = settings.incidents.max_list

    @server.tool(
        name="get_system_health",
        annotations=_READ,
        description=(
            "Measure current CPU, memory, commit and disk I/O over a short window and rank the "
            "top contributing processes by exact identity."
        ),
    )
    async def get_system_health() -> HealthResponse:
        return to_health(await _run(container.get_system_health.execute))

    @server.tool(
        name="diagnose_slowdown",
        annotations=_READ,
        description=(
            "Explain why the machine is (or recently was) slow: incidents recorded by the agent "
            "in the lookback window, a fresh measurement and hung-window verdicts become ranked "
            "findings with evidence, confidence rationale, affected processes and candidate "
            "repairs (planning only; nothing is executed)."
        ),
    )
    async def diagnose_slowdown(
        since_minutes: Annotated[
            int,
            Field(ge=1, le=max_lookback, description=f"lookback window (1-{max_lookback})"),
        ] = default_lookback,
    ) -> DiagnosisResponse:
        return to_diagnosis(
            await _run(container.diagnose_slowdown.execute, timedelta(minutes=since_minutes))
        )

    @server.tool(
        name="inspect_process",
        annotations=_READ,
        description=(
            "Describe one process: exact identity, executable, command line, tree context "
            "(parent, ancestors, descendants), protection level and risk markers. Giving "
            "create_time makes the lookup fail on a reused PID instead of describing a stranger."
        ),
    )
    async def inspect_process(
        pid: Pid, create_time: CreateTime | None = None
    ) -> ProcessInspectionResponse:
        moment = None if create_time is None else _parse_create_time(create_time)
        return to_process_inspection(await _run(container.inspect_process.execute, pid, moment))

    @server.tool(
        name="inspect_port",
        annotations=_READ,
        description=(
            "Resolve what listens on a TCP port to exact process identities with tree, "
            "protection and risk context, and whether clear_port would be eligible."
        ),
    )
    async def inspect_port(port: Port) -> PortInspectionResponse:
        return to_port_inspection(await _run(container.inspect_port.execute, port))

    @server.tool(
        name="list_recent_incidents",
        annotations=_READ,
        description="List pressure incidents recorded by the background agent, newest first.",
    )
    async def list_recent_incidents(
        limit: Annotated[int, Field(ge=1, le=max_incidents, description="at most this many")] = 10,
    ) -> IncidentListResponse:
        return to_incidents(await _run(container.list_recent_incidents.execute, limit))

    @server.tool(
        name="terminate_process",
        annotations=_MUTATION,
        description=(
            "MUTATION: terminate one exact process identity (or, with scope=tree, its whole "
            "tree, parents first). The target is revalidated on a fresh snapshot, protected and "
            "critical targets are rejected before any OS call, the result is verified by "
            "observation and audited. Returns the structured before/after record."
        ),
    )
    async def terminate_process(
        pid: Pid, create_time: CreateTime, scope: Literal["process", "tree"] = "process"
    ) -> RepairResponse:
        moment = _parse_create_time(create_time)
        return to_repair(
            await _run(container.terminate_process.execute, pid, moment, RepairScope(scope))
        )

    @server.tool(
        name="clear_port",
        annotations=_MUTATION,
        description=(
            "MUTATION: terminate the confirmed owner(s) of a TCP port and verify that nothing "
            "listens on it afterwards. Protected or unresolved owners are rejected. Audited."
        ),
    )
    async def clear_port(port: Port) -> RepairResponse:
        return to_repair(await _run(container.clear_port.execute, port))

    @server.tool(
        name="restart_windows_component",
        annotations=_MUTATION,
        description=(
            "MUTATION: restart the session's shell (explorer) or compositor (dwm) by exact "
            "identity and verify a healthy replacement. dwm is high risk, needs UAC elevation "
            "and is rejected unless enabled in configuration. Audited."
        ),
    )
    async def restart_windows_component(
        component: Literal["explorer", "dwm"],
    ) -> RepairResponse:
        return to_repair(
            await _run(container.restart_windows_component.execute, WindowsComponent(component))
        )

    return server


async def _run[T](use_case: Callable[..., T], *arguments: object) -> T:
    """Run one blocking use case off the event loop; expected failures become tool errors."""
    try:
        return await anyio.to_thread.run_sync(functools.partial(use_case, *arguments))
    except WindowsMedicError as exc:
        raise ToolError(str(exc)) from exc
    except ValueError as exc:
        raise ToolError(f"invalid argument: {exc}") from exc


def _parse_create_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolError(f"create_time is not an ISO 8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ToolError("create_time must include a timezone offset")
    return parsed


def __getattr__(name: str) -> MCPServer:
    """Expose ``server`` for ``mcp dev``/``mcp run`` discovery without import-time effects.

    ``MCPServer.__init__`` calls ``logging.basicConfig``; building it at import time would
    install the SDK's handler before bootstrap configures structured logging and every
    event would be emitted twice. The console entry point builds its own instance in
    :func:`main` after logging is configured.
    """
    if name == "server":
        container = try_compose(
            PROGRAM, environ=os.environ, log_stream=sys.stderr, error_stream=sys.stderr
        )
        if container is None:
            raise RuntimeError(f"{PROGRAM}: configuration error (see stderr)")
        atexit.register(container.close)  # the Inspector owns the process lifetime
        return create_server(container)
    raise AttributeError(name)


def _serve_stdio(mcp_server: MCPServer) -> None:
    mcp_server.run("stdio")


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    serve: Callable[[MCPServer], None] = _serve_stdio,
) -> int:
    """Run the MCP server entry point and return the process exit code."""
    environ = os.environ if environ is None else environ
    stdout = sys.stdout if stdout is None else stdout
    # stdout carries the MCP transport, which the SDK writes as UTF-8 itself.
    stderr = utf8_text(sys.stderr if stderr is None else stderr)

    parser = argparse.ArgumentParser(
        prog=PROGRAM, description="Windows Medic MCP server for Claude Code (stdio)."
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    arguments = parser.parse_args(argv)

    if arguments.version:
        stdout.write(f"{PROGRAM} {windows_medic.__version__}\n")
        return 0

    container = try_compose(PROGRAM, environ=environ, log_stream=stderr, error_stream=stderr)
    if container is None:
        return EXIT_CONFIGURATION_ERROR

    try:
        log_event(
            _logger,
            "mcp.server.starting",
            pid=os.getpid(),
            transport="stdio",
            tool_count=len(READ_TOOLS) + len(MUTATION_TOOLS),
        )
        serve(create_server(container))
    finally:
        container.close()
    return 0
