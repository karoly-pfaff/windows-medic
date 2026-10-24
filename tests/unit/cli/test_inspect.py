"""`windows-medic inspect`: identity, tree context, protection and risk at the boundary."""

import io
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta
from typing import TextIO

import pytest

from tests.builders import BOOT, process, process_snapshot
from tests.containers import fake_container
from tests.fakes import FakeProcessReader
from windows_medic.application.use_cases.inspect_process import InspectProcess
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessObservation
from windows_medic_cli import main as cli_main
from windows_medic_cli.render import render_inspection
from windows_medic_root.container import Container


def at(seconds: int) -> datetime:
    return BOOT + timedelta(seconds=seconds)


TERMINAL = process(1, created=BOOT, name="WindowsTerminal.exe")
SHELL = process(2, created=BOOT + timedelta(seconds=1), parent_pid=1, name="pwsh.exe")
TARGET = process(
    3,
    created=BOOT + timedelta(seconds=2),
    parent_pid=2,
    name="node.exe",
    cpu_time_seconds=12.5,
    working_set_bytes=256 * 1024**2,
)
CHILD = process(4, created=BOOT + timedelta(seconds=3), parent_pid=3, name="esbuild.exe")
ORPHAN = process(9, created=BOOT + timedelta(seconds=4), parent_pid=777, name="vite.exe")
CRITICAL = process(4242, created=BOOT, name="python.exe")


def container(*observations: ProcessObservation) -> Container:
    snapshot = process_snapshot(*(observations or (TERMINAL, SHELL, TARGET, CHILD, ORPHAN)))
    return fake_container(process_reader=FakeProcessReader(snapshot))


def composer(built: Container) -> cli_main.Composer:
    def compose(
        program: str, *, environ: Mapping[str, str], log_stream: TextIO, error_stream: TextIO
    ) -> Container | None:
        return built

    return compose


def run(*argv: str, built: Container | None = None) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = cli_main.main(
        list(argv),
        environ={},
        stdout=stdout,
        stderr=stderr,
        compose=composer(built or container()),
    )
    return code, stdout.getvalue(), stderr.getvalue()


class TestRenderInspection:
    def test_identity_and_observation_facts(self) -> None:
        text = render_inspection(container().inspect_process.execute(3))

        assert text.startswith("Process node.exe (pid 3, created 2026-09-11T09:00:02+00:00)")
        assert "Executable: C:\\bin\\node.exe" in text
        assert "Command line: node.exe" in text
        assert "User: DESKTOP\\user (session 1)" in text
        assert "CPU time: 12.5 s" in text
        assert "Working set: 256.0 MiB" in text
        assert "Threads: 4, handles: 120" in text

    def test_tree_context(self) -> None:
        text = render_inspection(container().inspect_process.execute(3))

        assert "Parent: pwsh.exe (pid 2)" in text
        assert (
            "Ancestors (nearest first):\n  pwsh.exe (pid 2)\n  WindowsTerminal.exe (pid 1)" in text
        )
        assert "Descendants: 1\n  esbuild.exe (pid 4, depth 1)" in text

    def test_protection_and_risk(self) -> None:
        text = render_inspection(container().inspect_process.execute(3))

        assert "Protection: none" in text
        assert "Risk markers: terminal_ancestry" in text

    def test_unresolved_parent_is_explained(self) -> None:
        text = render_inspection(container().inspect_process.execute(9))

        assert "Parent: pid 777 (parent_gone)" in text
        assert "Ancestors (nearest first):\n  (none: parent unresolved)" in text
        assert "Risk markers: unresolved_parent" in text

    def test_protected_process_shows_reasons(self) -> None:
        text = render_inspection(container(CRITICAL).inspect_process.execute(4242))

        assert "Protection: protected (windows_medic_self)" in text

    def test_unavailable_fields_are_explicit(self) -> None:
        hidden = ProcessObservation(
            **{
                **{slot: getattr(TARGET, slot) for slot in TARGET.__slots__},
                "exe_path": Unavailable(UnavailableReason.ACCESS_DENIED),
                "command_line": Unavailable(UnavailableReason.ACCESS_DENIED),
            }
        )

        text = render_inspection(container(hidden).inspect_process.execute(3))

        assert "Executable: n/a (access_denied)" in text
        assert "Command line: n/a (access_denied)" in text

    def test_ancestor_truncation_and_zero_ancestor_limit_are_rendered(self) -> None:
        deep = [process(pid, created=at(pid), parent_pid=pid - 1) for pid in range(11, 20)]
        root = process(10, created=BOOT)
        built = container(root, *deep)

        text = render_inspection(built.inspect_process.execute(19))
        assert "  ... (more ancestors not shown)" in text

        fresh = container(root, *deep)
        use_case = InspectProcess(
            process_reader=fresh.process_reader,
            protection=fresh.protection_policy,
            ancestry=fresh.ancestry_policy,
            limits=replace(fresh.inspect_process.limits, max_ancestors=0),
        )
        text = render_inspection(use_case.execute(19))
        assert "Parent: pid 18" in text
        assert "  ... (ancestors not shown)" in text
        assert "(none: parent unresolved)" not in text

    def test_cycle_stop_is_explained(self) -> None:
        a = process(1, created=BOOT, parent_pid=2)
        b = process(2, created=BOOT, parent_pid=1)

        text = render_inspection(container(a, b).inspect_process.execute(1))

        assert "  ... (walk stopped: cycle)" in text

        lonely = container(process(1, created=BOOT, parent_pid=1))
        assert "(none: parent unresolved)" in render_inspection(lonely.inspect_process.execute(1))

    def test_truncation_is_reported(self) -> None:
        root = process(100, created=BOOT)
        kids = [process(pid, created=at(1), parent_pid=100) for pid in range(101, 110)]

        text = render_inspection(container(root, *kids).inspect_process.execute(100))

        assert "Descendants: 5 shown (more exist)" in text


class TestInspectCommand:
    def test_inspects_by_pid(self) -> None:
        code, out, err = run("inspect", "3")

        assert code == 0
        assert out.startswith("Process node.exe (pid 3")
        assert err == ""

    def test_accepts_an_exact_create_time(self) -> None:
        code, out, _ = run("inspect", "3", "--create-time", TARGET.identity.create_time.isoformat())

        assert code == 0
        assert "pid 3" in out

    def test_stale_identity_is_reported_with_exit_code_1(self) -> None:
        code, out, err = run("inspect", "3", "--create-time", "2020-01-01T00:00:00+00:00")

        assert code == 1
        assert out == ""
        assert err.startswith("windows-medic: pid 3 @ 2020-01-01T00:00:00+00:00 no longer exists")

    def test_unknown_pid_is_reported_with_exit_code_1(self) -> None:
        code, _, err = run("inspect", "999")

        assert code == 1
        assert err == "windows-medic: no process with pid 999 exists\n"

    def test_names_outside_the_console_code_page_do_not_crash_redirected_output(self) -> None:
        # `windows-medic inspect 3 > out.txt` on a cp1250 machine; Claude's terminal title "✳".
        built = container(process(3, name="✳ claude.exe"))
        raw = io.BytesIO()
        stdout = io.TextIOWrapper(raw, encoding="cp1250", errors="strict", newline="")

        code = cli_main.main(
            ["inspect", "3"],
            environ={},
            stdout=stdout,
            stderr=io.StringIO(),
            compose=composer(built),
        )
        stdout.flush()

        assert code == 0
        assert "✳ claude.exe".encode() in raw.getvalue()  # UTF-8, not the ANSI code page

    @pytest.mark.parametrize(
        "argv", [("inspect",), ("inspect", "-1"), ("inspect", "abc"), ("inspect", str(2**63))]
    )
    def test_invalid_arguments_are_usage_errors(self, argv: tuple[str, ...]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            run(*argv)

        assert excinfo.value.code == 2

    def test_malformed_create_time_is_a_usage_error(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            run("inspect", "3", "--create-time", "yesterday")

        assert excinfo.value.code == 2

    def test_naive_create_time_is_a_usage_error(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            run("inspect", "3", "--create-time", "2026-09-11T09:00:02")

        assert excinfo.value.code == 2

    def test_no_arguments_lists_the_inspect_command(self) -> None:
        code, out, _ = run()

        assert code == 0
        assert "inspect" in out
