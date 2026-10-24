"""MCP contract tests: tool schemas, input bounds, response shapes and error mapping.

The server is exercised in-process through ``MCPServer.call_tool`` over the fake
container, so every tool runs its real handler, schema validation and result conversion
without a transport.
"""

import json
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

import anyio
import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult

from tests.builders import BOOT, T0, identity, incident, listener, process, process_snapshot
from tests.containers import fake_container
from tests.fakes import (
    FakeClock,
    FakeIncidentRepository,
    FakeProcessReader,
    FakeProcessWorld,
    FakeRepairAudit,
    FakeWorldNetworkReader,
)
from windows_medic.domain.errors import RepairAuditError
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.repair import RepairRecord
from windows_medic_mcp.server import MUTATION_TOOLS, READ_TOOLS, create_server
from windows_medic_root.container import Container


def iso(moment: datetime) -> str:
    """Pydantic serialises UTC datetimes with ``Z``; fromisoformat accepts it back."""
    return moment.isoformat().replace("+00:00", "Z")


CREATED = iso(BOOT)


def call(server: MCPServer, name: str, **arguments: Any) -> dict[str, Any]:  # noqa: ANN401
    """Call a tool and return its structured content (asserting the text mirrors it)."""

    async def run() -> CallToolResult:
        result = await server.call_tool(name, arguments)
        assert isinstance(result, CallToolResult)
        return result

    result = anyio.run(run)
    assert result.is_error is not True
    assert result.structured_content is not None
    text = result.content[0]
    assert text.type == "text"
    assert json.loads(text.text) == result.structured_content
    return dict(result.structured_content)


def error(server: MCPServer, name: str, **arguments: Any) -> str:  # noqa: ANN401
    async def run() -> str:
        try:
            await server.call_tool(name, arguments)
        except ToolError as exc:
            return str(exc)
        raise AssertionError("expected a tool error")

    return anyio.run(run)


def world_container(
    *, listeners: tuple[Any, ...] = (), audit: FakeRepairAudit | None = None
) -> tuple[Container, FakeProcessWorld]:
    world = FakeProcessWorld(
        FakeClock(T0),
        process(4, name="explorer.exe"),
        process(4242, name="windows-medic.exe"),
        process(10, name="node.exe", parent_pid=4),
        process(11, name="esbuild.exe", parent_pid=10),
        process(300, name="dwm.exe"),
    )
    built = fake_container(
        process_reader=world,
        process_controller=world,
        network_reader=FakeWorldNetworkReader(world, *listeners),
        repair_audit=audit,
    )
    return built, world


class BrokenAudit(FakeRepairAudit):
    def save(self, record: RepairRecord) -> None:
        raise RepairAuditError("database is locked")


class TestSchema:
    def test_exactly_the_v1_tools_are_exposed_with_honest_annotations(self) -> None:
        server = create_server(fake_container())

        tools = anyio.run(server.list_tools)

        assert [t.name for t in tools] == [*READ_TOOLS, *MUTATION_TOOLS]
        for tool in tools:
            assert tool.annotations is not None
            expected_read_only = tool.name in READ_TOOLS
            assert tool.annotations.read_only_hint is expected_read_only
            assert tool.annotations.destructive_hint is (not expected_read_only)
            assert tool.output_schema is not None
            if not expected_read_only:
                assert tool.description is not None
                assert tool.description.startswith("MUTATION:")

    def test_input_schemas_carry_the_bounds(self) -> None:
        server = create_server(fake_container())
        schemas = {t.name: t.input_schema for t in anyio.run(server.list_tools)}

        port = schemas["inspect_port"]["$defs"]["Port"]
        assert (port["minimum"], port["maximum"]) == (1, 65535)
        assert schemas["inspect_process"]["$defs"]["Pid"]["minimum"] == 0
        assert schemas["inspect_process"]["required"] == ["pid"]
        since = schemas["diagnose_slowdown"]["properties"]["since_minutes"]
        assert (since["minimum"], since["maximum"], since["default"]) == (1, 240, 30)
        limit = schemas["list_recent_incidents"]["properties"]["limit"]
        assert (limit["minimum"], limit["maximum"], limit["default"]) == (1, 50, 10)
        assert schemas["terminate_process"]["required"] == ["pid", "create_time"]
        assert schemas["terminate_process"]["properties"]["scope"]["enum"] == ["process", "tree"]
        assert schemas["restart_windows_component"]["properties"]["component"]["enum"] == [
            "explorer",
            "dwm",
        ]


class TestReadTools:
    def test_get_system_health(self) -> None:
        payload = call(create_server(fake_container()), "get_system_health")

        assert payload["cpu_percent"] == 25.0
        assert payload["cpu_count"] == 8
        assert payload["memory"]["percent_used"] == 50.0
        assert payload["top_cpu"][0]["process"] == {"pid": 10, "create_time": CREATED}
        assert payload["top_cpu"][0]["cpu_percent"] == 25.0
        assert payload["top_cpu"][0]["name"] == "node.exe"

    def test_inspect_process_by_pid_and_by_exact_identity(self) -> None:
        built, _ = world_container()
        server = create_server(built)

        payload = call(server, "inspect_process", pid=11)
        exact = call(server, "inspect_process", pid=11, create_time=CREATED)

        assert payload == exact
        assert payload["process"]["process"] == {"pid": 11, "create_time": CREATED}
        assert payload["process"]["name"] == "esbuild.exe"
        assert payload["parent"] == {"pid": 10, "create_time": CREATED}
        assert [a["process"]["pid"] for a in payload["ancestors"]] == [10, 4]
        assert payload["protection"] == {"level": "none", "reasons": []}

    def test_inspect_process_reports_unavailable_fields_explicitly(self) -> None:
        payload = call(create_server(fake_container()), "inspect_process", pid=10)

        assert payload["parent"] == {"parent_pid": 4, "reason": "parent_gone"}
        assert payload["risk_markers"] == ["unresolved_parent"]

    def test_inspect_port(self) -> None:
        built, _ = world_container(listeners=(listener(3000, 11),))

        payload = call(create_server(built), "inspect_port", port=3000)

        assert payload["port"] == 3000
        assert payload["owners"][0]["process"]["pid"] == 11
        assert payload["owners"][0]["endpoints"][0]["port"] == 3000
        assert payload["clear_port"] == {"eligible": True, "blockers": []}

    def test_list_recent_incidents_is_bounded_newest_first(self) -> None:
        repository = FakeIncidentRepository()
        for n in range(5):
            repository.save(incident(f"inc-{n}", started_at=T0 - timedelta(minutes=30 - n)))
        server = create_server(fake_container(incident_repository=repository))

        payload = call(server, "list_recent_incidents", limit=2)

        assert [i["id"] for i in payload["incidents"]] == ["inc-4", "inc-3"]
        assert payload["incidents"][0]["kind"] == "cpu_pressure"

    def test_diagnose_slowdown_returns_ranked_findings_with_rationale(self) -> None:
        repository = FakeIncidentRepository()
        repository.save(incident("inc-1", started_at=T0 - timedelta(minutes=5)))
        server = create_server(fake_container(incident_repository=repository))

        payload = call(server, "diagnose_slowdown", since_minutes=15)

        assert payload["lookback"]["since"] == iso(T0 - timedelta(minutes=15))
        assert payload["incidents"][0]["id"] == "inc-1"
        kinds = [f["kind"] for f in payload["findings"]]
        assert "cpu_pressure" in kinds
        pressure = next(f for f in payload["findings"] if f["kind"] == "cpu_pressure")
        assert pressure["confidence"]["raised_by"] == ["sustained_incident"]
        assert pressure["evidence"][0]["incident_id"] == "inc-1"
        assert payload["evidence"]["incidents_in_window"] == 1
        assert payload["current"]["cpu_percent"] == 25.0


class TestBounds:
    def test_invalid_ports_pids_lookbacks_and_limits_are_rejected(self) -> None:
        server = create_server(fake_container())

        assert "less than or equal to 65535" in error(server, "inspect_port", port=70000)
        assert "greater than or equal to 1" in error(server, "clear_port", port=0)
        assert "greater than or equal to 0" in error(server, "inspect_process", pid=-1)
        # Windows pids are 32-bit; a larger value must not reach the audit's SQLite integer.
        assert "less than or equal to 4294967295" in error(
            server, "terminate_process", pid=2**63, create_time=CREATED
        )
        assert "less than or equal to 240" in error(server, "diagnose_slowdown", since_minutes=241)
        assert "greater than or equal to 1" in error(server, "list_recent_incidents", limit=0)
        assert "'explorer' or 'dwm'" in error(server, "restart_windows_component", component="x")
        assert "'process' or 'tree'" in error(
            server, "terminate_process", pid=10, create_time=CREATED, scope="all"
        )
        assert "create_time" in error(server, "terminate_process", pid=10)

    def test_create_time_must_be_an_aware_iso_timestamp(self) -> None:
        server = create_server(fake_container())

        assert "not an ISO 8601 timestamp" in error(
            server, "inspect_process", pid=10, create_time="yesterday"
        )
        assert "timezone offset" in error(
            server, "inspect_process", pid=10, create_time="2026-09-11T09:00:00"
        )

    def test_output_is_bounded_by_the_configured_limits(self) -> None:
        children = [process(pid, name="w.exe", parent_pid=10) for pid in range(100, 112)]
        long_command = ("node.exe", "x" * 2000)
        root = replace(process(10, name="node.exe"), command_line=long_command)
        snapshot = process_snapshot(root, *children)
        server = create_server(fake_container(process_reader=FakeProcessReader(snapshot)))

        payload = call(server, "inspect_process", pid=10)

        assert len(payload["descendants"]) == 5
        assert payload["descendants_truncated"] is True
        assert len(payload["process"]["command_line"]) == 512
        assert payload["process"]["command_line"].endswith("...")


class TestErrorMapping:
    def test_expected_application_errors_become_tool_errors_with_the_message(self) -> None:
        built, _ = world_container()
        server = create_server(built)

        assert error(server, "inspect_process", pid=99) == (
            "Error executing tool inspect_process: no process with pid 99 exists"
        )
        stale = iso(BOOT + timedelta(seconds=1))
        assert "no longer exists" in error(server, "inspect_process", pid=10, create_time=stale)

    def test_audit_failures_are_reported_not_traced(self) -> None:
        built, world = world_container(audit=BrokenAudit())
        server = create_server(built)

        assert error(server, "terminate_process", pid=11, create_time=CREATED) == (
            "Error executing tool terminate_process: database is locked"
        )
        assert world.terminations == []


class TestMutationTools:
    def test_terminate_process_returns_the_structured_before_after_record(self) -> None:
        built, world = world_container()

        payload = call(
            create_server(built), "terminate_process", pid=10, create_time=CREATED, scope="tree"
        )

        assert payload["mutation"] is True
        assert payload["action"] == "process.terminate_tree"
        assert payload["status"] == "succeeded"
        assert payload["before"]["target"] == {"pid": 10, "create_time": CREATED}
        assert payload["before"]["risk"] == "low"
        assert [m["process"]["pid"] for m in payload["after"]["members"]] == [10, 11]
        assert payload["after"]["verification"]["passed"] is True
        assert world.terminations == [identity(10), identity(11)]

    def test_a_rejected_repair_is_a_result_not_an_error(self) -> None:
        built, world = world_container()

        payload = call(create_server(built), "terminate_process", pid=4, create_time=CREATED)

        assert payload["status"] == "rejected"
        assert payload["rejection"] == "target_protected"
        assert payload["before"]["risk"] == "high"
        assert payload["after"]["members"] == []
        assert world.terminations == []

    def test_clear_port(self) -> None:
        built, world = world_container(listeners=(listener(3000, 11),))

        payload = call(create_server(built), "clear_port", port=3000)

        assert payload["action"] == "port.clear"
        assert payload["status"] == "succeeded"
        assert payload["before"]["port"] == 3000
        assert "port 3000 has no listener" in payload["after"]["verification"]["detail"]
        assert world.terminations == [identity(11)]

    def test_restart_windows_component_dwm_is_rejected_by_default(self) -> None:
        built, world = world_container()

        payload = call(create_server(built), "restart_windows_component", component="dwm")

        assert payload["action"] == "windows.dwm.restart"
        assert payload["status"] == "rejected"
        assert payload["rejection"] == "high_risk_disabled"
        assert payload["before"]["requires_elevation"] is True
        assert world.terminations == []


def test_the_server_names_itself_for_clients() -> None:
    server = create_server(fake_container())

    assert server.name == "windows-medic"
    assert server.instructions is not None
    assert "never run automatically" in server.instructions


@pytest.mark.parametrize("name", [*READ_TOOLS, *MUTATION_TOOLS])
def test_every_tool_has_a_structured_output_schema(name: str) -> None:
    server = create_server(fake_container())
    tools = {t.name: t for t in anyio.run(server.list_tools)}

    schema = tools[name].output_schema
    assert schema is not None
    assert schema["type"] == "object"


class TestUnavailableAndUnresolved:
    def test_unavailable_fields_and_unresolved_listeners_are_explicit(self) -> None:
        denied = Unavailable(UnavailableReason.ACCESS_DENIED)
        hidden = replace(
            process(20, name="svc.exe", parent_pid=4), command_line=denied, working_set_bytes=denied
        )
        world = FakeProcessWorld(FakeClock(T0), process(4, name="explorer.exe"), hidden)
        built = fake_container(
            process_reader=world,
            process_controller=world,
            network_reader=FakeWorldNetworkReader(world, listener(3000, 20), listener(3001, None)),
        )
        server = create_server(built)

        inspected = call(server, "inspect_process", pid=20)
        owned = call(server, "inspect_port", port=3000)
        orphan = call(server, "inspect_port", port=3001)

        assert inspected["process"]["command_line"] == {"unavailable": "access_denied"}
        assert inspected["process"]["working_set_bytes"] == {"unavailable": "access_denied"}
        assert owned["owners"][0]["command_line"] == {"unavailable": "access_denied"}
        assert orphan["owners"] == []
        assert orphan["unresolved"] == [
            {
                "endpoint": {
                    "protocol": "tcp",
                    "family": "ipv4",
                    "address": "127.0.0.1",
                    "port": 3001,
                    "reported_pid": None,
                },
                "reported_pid": None,
                "reason": "owner_unknown",
            }
        ]
        assert orphan["clear_port"]["blockers"] == ["owner_unresolved"]

    def test_boundary_value_errors_from_use_cases_are_tool_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = fake_container()

        def rejecting(port: int) -> object:
            raise ValueError(f"port must be between 1 and 65535, got {port}")

        monkeypatch.setattr(built.inspect_port, "execute", rejecting)

        assert error(create_server(built), "inspect_port", port=8080) == (
            "Error executing tool inspect_port: invalid argument: "
            "port must be between 1 and 65535, got 8080"
        )
