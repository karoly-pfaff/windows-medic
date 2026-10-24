"""`windows-medic terminate|clear-port|repairs`: explicit repairs rendered at the boundary."""

import io
from collections.abc import Mapping
from dataclasses import replace
from datetime import timedelta
from typing import TextIO

import pytest

from tests.builders import BOOT, T0, identity, listener, process
from tests.containers import fake_container
from tests.fakes import FakeClock, FakeProcessWorld, FakeRepairAudit, FakeWorldNetworkReader
from windows_medic.domain.errors import RepairAuditError
from windows_medic.domain.models.network import ListeningEndpoint
from windows_medic.domain.models.repair import RepairRecord, RepairScope, RepairStatus
from windows_medic_cli import main as cli_main
from windows_medic_cli.render import render_repair, render_repairs
from windows_medic_root.container import Container

CREATED = BOOT.isoformat()


class BrokenAudit(FakeRepairAudit):
    def save(self, record: RepairRecord) -> None:
        raise RepairAuditError("database is locked")

    def recent(self, *, limit: int) -> tuple[RepairRecord, ...]:
        raise RepairAuditError("database is locked")


def composer(built: Container) -> cli_main.Composer:
    def compose(
        program: str, *, environ: Mapping[str, str], log_stream: TextIO, error_stream: TextIO
    ) -> Container | None:
        return built

    return compose


def run(*argv: str, built: Container) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = cli_main.main(
        list(argv), environ={}, stdout=stdout, stderr=stderr, compose=composer(built)
    )
    return code, stdout.getvalue(), stderr.getvalue()


def world_container(
    *, listeners: tuple[ListeningEndpoint, ...] = (), audit: FakeRepairAudit | None = None
) -> tuple[Container, FakeProcessWorld]:
    world = FakeProcessWorld(
        FakeClock(T0),
        process(4, name="explorer.exe"),
        process(10, name="node.exe", parent_pid=4),
        process(11, name="esbuild.exe", parent_pid=10),
    )
    built = fake_container(
        process_reader=world,
        process_controller=world,
        network_reader=FakeWorldNetworkReader(world, *listeners),
        repair_audit=audit,
    )
    return built, world


class TestTerminate:
    def test_terminates_by_exact_identity_and_renders_the_record(self) -> None:
        built, world = world_container()

        code, out, err = run("terminate", "10", "--create-time", CREATED, built=built)

        assert code == 0
        assert err == ""
        lines = out.splitlines()
        assert lines[0].startswith("Repair ")
        assert lines[0].endswith(": process.terminate pid 10 @ " + CREATED + " -> succeeded")
        assert "Risk: low" in out
        assert "Members (1 of 1 gone):" in out
        assert "  10  esbuild.exe" not in out
        assert "terminated" in out
        assert "Verification: passed (1 of 1 members gone)" in out
        assert world.terminations == [identity(10)]

    def test_tree_flag_terminates_the_tree(self) -> None:
        built, world = world_container()

        code, out, _ = run("terminate", "10", "--create-time", CREATED, "--tree", built=built)

        assert code == 0
        assert "process.terminate_tree" in out
        assert "Members (2 of 2 gone):" in out
        assert world.terminations == [identity(10), identity(11)]

    def test_a_rejected_repair_exits_non_zero_with_the_reason(self) -> None:
        built, world = world_container()
        stale = (BOOT + timedelta(seconds=1)).isoformat()

        code, out, err = run("terminate", "10", "--create-time", stale, built=built)

        assert code == 1
        assert err == ""
        assert "-> rejected (stale_identity)" in out
        assert world.terminations == []

    def test_a_protected_target_is_rejected(self) -> None:
        built, world = world_container()

        code, out, _ = run("terminate", "4", "--create-time", CREATED, built=built)

        assert code == 1
        assert "rejected (target_protected)" in out
        assert world.terminations == []

    def test_create_time_is_mandatory(self) -> None:
        built, _ = world_container()

        with pytest.raises(SystemExit) as excinfo:
            run("terminate", "10", built=built)

        assert excinfo.value.code == 2

    def test_audit_failure_is_reported_without_a_traceback(self) -> None:
        built, world = world_container(audit=BrokenAudit())

        code, out, err = run("terminate", "10", "--create-time", CREATED, built=built)

        assert code == 1
        assert out == ""
        assert err == "windows-medic: database is locked\n"
        assert world.terminations == []


class TestClearPort:
    def test_clears_the_port_and_verifies(self) -> None:
        built, world = world_container(listeners=(listener(3000, 11),))

        code, out, _ = run("clear-port", "3000", built=built)

        assert code == 0
        assert ": port.clear port 3000 (pid 11 @ " in out
        assert "-> succeeded" in out
        assert "Verification: passed (1 of 1 members gone; port 3000 has no listener)" in out
        assert world.terminations == [identity(11)]

    def test_nothing_listening_is_rejected(self) -> None:
        built, _ = world_container()

        code, out, _ = run("clear-port", "3000", built=built)

        assert code == 1
        assert ": port.clear port 3000 -> rejected (port_not_listening)" in out

    @pytest.mark.parametrize("value", ["0", "70000", "http"])
    def test_invalid_port_is_a_usage_error(self, value: str) -> None:
        built, _ = world_container()

        with pytest.raises(SystemExit) as excinfo:
            run("clear-port", value, built=built)

        assert excinfo.value.code == 2


class TestRepairs:
    def test_lists_the_audit_newest_first(self) -> None:
        built, _ = world_container()
        run("terminate", "11", "--create-time", CREATED, built=built)
        assert isinstance(built.clock, FakeClock)
        built.clock.current += timedelta(seconds=1)
        run("clear-port", "3000", built=built)

        code, out, _ = run("repairs", built=built)

        assert code == 0
        lines = out.splitlines()
        assert lines[0] == "Recent repairs: 2 (newest first)"
        assert lines[1].split() == ["ID", "Action", "Status", "Target", "Requested", "Outcome"]
        assert "port.clear" in lines[2]
        assert "rejected" in lines[2]
        assert "port_not_listening" in lines[2]
        assert "process.terminate" in lines[3]
        assert "succeeded" in lines[3]

    def test_empty(self) -> None:
        built, _ = world_container()

        code, out, _ = run("repairs", "--limit", "3", built=built)

        assert code == 0
        assert out == "No repairs recorded.\n"

    def test_no_arguments_lists_the_repair_commands(self) -> None:
        built, _ = world_container()

        code, out, _ = run(built=built)

        assert code == 0
        assert "terminate <pid> --create-time" in out
        assert "clear-port <port>" in out


class TestRender:
    def test_render_repair_shows_members_drift_and_verification(self) -> None:
        built, world = world_container()
        world.denied.add(identity(11))
        record = built.terminate_process.execute(10, BOOT, scope=RepairScope.TREE)

        text = render_repair(record)

        assert record.status is RepairStatus.PARTIAL
        assert "-> partial" in text
        assert "Members (1 of 2 gone):" in text
        assert "access_denied" in text
        assert "access is denied" in text
        assert "Verification: failed (1 of 2 members gone; still running: pid 11)" in text

    def test_render_repairs_empty(self) -> None:
        assert render_repairs(()) == "No repairs recorded.\n"


class TestErrorPaths:
    def test_clear_port_audit_failure_is_reported(self) -> None:
        built, world = world_container(listeners=(listener(3000, 11),), audit=BrokenAudit())

        code, out, err = run("clear-port", "3000", built=built)

        assert code == 1
        assert out == ""
        assert err == "windows-medic: database is locked\n"
        assert world.terminations == []

    def test_repairs_listing_failure_is_reported(self) -> None:
        built, _ = world_container(audit=BrokenAudit())

        code, out, err = run("repairs", built=built)

        assert code == 1
        assert out == ""
        assert err == "windows-medic: database is locked\n"


class TestRenderDetails:
    def test_drift_and_elevation_are_rendered(self) -> None:
        built, world = world_container()
        world.spawns[identity(11)] = process(12, name="node.exe", parent_pid=10, created=T0)
        record = built.terminate_process.execute(10, BOOT, scope=RepairScope.TREE)

        text = render_repair(record)

        assert "Appeared after the plan (not targeted): pid 12 @ " in text
        assert "-> partial" in text

    def test_a_started_record_renders_without_verification(self) -> None:
        built, world = world_container()
        record = built.terminate_process.execute(11, BOOT)
        started = replace(
            record,
            status=RepairStatus.STARTED,
            completed_at=None,
            members=(),
            verification=None,
            requires_elevation=True,
        )

        text = render_repair(started)
        table = render_repairs((started,))

        assert "-> started" in text
        assert "completed: -" in text
        assert "Risk: low, elevation required" in text
        assert "Verification: not performed" in text
        assert table.splitlines()[2].endswith("-")
        assert world.terminations == [identity(11)]

    def test_long_outcomes_are_truncated_in_the_table(self) -> None:
        built, _ = world_container()
        record = built.terminate_process.execute(11, BOOT)
        assert record.verification is not None
        verbose = replace(record, verification=replace(record.verification, detail="x" * 100))

        row = render_repairs((verbose,)).splitlines()[2]

        assert row.endswith("x" * 57 + "...")


class TestRestartComponent:
    def shell_container(self) -> tuple[Container, FakeProcessWorld]:
        world = FakeProcessWorld(
            FakeClock(T0),
            process(4242, name="windows-medic.exe"),
            process(100, name="explorer.exe"),
            process(300, name="dwm.exe"),
        )
        built = fake_container(process_reader=world, process_controller=world)
        return built, world

    def test_explorer_restart_reports_the_replacement(self) -> None:
        built, world = self.shell_container()
        world.spawns[identity(100)] = process(150, name="explorer.exe", created=T0)

        code, out, err = run("restart-component", "explorer", built=built)

        assert code == 0
        assert err == ""
        assert ": windows.explorer.restart pid 100 @ " in out
        assert "-> succeeded" in out
        assert "Replacement: pid 150 @ 2026-09-11T12:00:00+00:00" in out
        assert "Verification: passed (old instance gone; replacement pid 150" in out
        assert world.terminations == [identity(100)]

    def test_dwm_is_rejected_unless_high_risk_repairs_are_enabled(self) -> None:
        built, world = self.shell_container()

        code, out, _ = run("restart-component", "dwm", built=built)

        assert code == 1
        assert "windows.dwm.restart pid 300 @ " in out
        assert "-> rejected (high_risk_disabled)" in out
        assert "Risk: high, elevation required" in out
        assert world.terminations == []

    def test_unknown_components_are_a_usage_error(self) -> None:
        built, _ = self.shell_container()

        with pytest.raises(SystemExit) as excinfo:
            run("restart-component", "winlogon", built=built)

        assert excinfo.value.code == 2

    def test_no_arguments_lists_the_command(self) -> None:
        built, _ = self.shell_container()

        code, out, _ = run(built=built)

        assert code == 0
        assert "restart-component <explorer|dwm>" in out


def test_restart_component_audit_failure_is_reported_without_a_traceback() -> None:
    world = FakeProcessWorld(
        FakeClock(T0), process(4242, name="windows-medic.exe"), process(100, name="explorer.exe")
    )
    built = fake_container(
        process_reader=world, process_controller=world, repair_audit=BrokenAudit()
    )

    code, out, err = run("restart-component", "explorer", built=built)

    assert code == 1
    assert out == ""
    assert err == "windows-medic: database is locked\n"
    assert world.terminations == []
