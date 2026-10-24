"""`windows-medic port`: listener owners by exact identity, races and eligibility explicit."""

import io
from collections.abc import Mapping
from datetime import timedelta
from typing import TextIO

import pytest

from tests.builders import BOOT, T0, listener, process, process_snapshot
from tests.containers import fake_container
from tests.fakes import FakeNetworkReader, FakeProcessReader
from windows_medic.domain.models.network import AddressFamily, ListeningEndpoint
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.samples import ProcessSnapshot
from windows_medic_cli import main as cli_main
from windows_medic_cli.render import render_port_inspection
from windows_medic_root.container import Container

SHELL = process(1, created=BOOT, name="pwsh.exe")
NODE = process(100, created=BOOT + timedelta(seconds=1), parent_pid=1, name="node.exe")
SVCHOST = process(200, created=BOOT + timedelta(seconds=2), parent_pid=1, name="svchost.exe")
BASELINE = process_snapshot(SHELL, NODE, SVCHOST, observed_at=T0)


def container(
    *listeners: ListeningEndpoint,
    baseline: ProcessSnapshot = BASELINE,
    lookup: ProcessSnapshot | None = None,
) -> Container:
    return fake_container(
        process_reader=FakeProcessReader(baseline, lookup=lookup),
        network_reader=FakeNetworkReader(*listeners),
    )


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


class TestRenderPortInspection:
    def test_resolved_owner_with_context_and_eligibility(self) -> None:
        built = container(listener(5173, 100), listener(5173, 100, family=AddressFamily.IPV6))

        text = render_port_inspection(built.inspect_port.execute(5173))

        assert text.startswith("TCP port 5173 (observed 2026-09-11T12:00:00+00:00)")
        assert "Owners: 1" in text
        assert "  node.exe (pid 100, created 2026-09-11T09:00:01+00:00)" in text
        assert "    Listening on: 127.0.0.1:5173 (ipv4), [::1]:5173 (ipv6)" in text
        assert "    Executable: C:\\bin\\node.exe" in text
        assert "    Command line: node.exe" in text
        assert "    Parent: pwsh.exe (pid 1)" in text
        assert "    Protection: none" in text
        assert "    Risk markers: terminal_ancestry" in text
        assert "Clear-port plan: eligible (all listeners resolved and unprotected)" in text

    def test_closed_port(self) -> None:
        text = render_port_inspection(container().inspect_port.execute(5173))

        assert "Owners: 0" in text
        assert "  (nothing is listening on this port)" in text
        assert "Clear-port plan: not eligible (no_owner)" in text

    def test_protected_owner_blocks_clearing(self) -> None:
        text = render_port_inspection(container(listener(135, 200)).inspect_port.execute(135))

        assert "  svchost.exe (pid 200" in text
        assert "    Protection: windows_component (windows_component_name)" in text
        assert "Clear-port plan: not eligible (owner_protected)" in text

    def test_unresolved_owner_is_reported_as_a_race(self) -> None:
        after = process_snapshot(SHELL, SVCHOST, observed_at=T0)
        built = container(listener(5173, 100), lookup=after)

        text = render_port_inspection(built.inspect_port.execute(5173))

        assert "Unresolved listeners: 1" in text
        assert "  127.0.0.1:5173 (ipv4) reported pid 100: owner_changed" in text
        assert "Clear-port plan: not eligible (owner_unresolved)" in text

    def test_unknown_pid_and_truncation_are_explicit(self) -> None:
        crowd = [
            process(pid, created=BOOT + timedelta(seconds=pid), name="node.exe")
            for pid in range(300, 306)
        ]
        listeners = [listener(5173, pid) for pid in range(300, 306)] + [listener(5173, None)]
        built = container(*listeners, baseline=process_snapshot(*crowd, observed_at=T0))

        text = render_port_inspection(built.inspect_port.execute(5173))

        assert "Owners: 3 shown (more exist)" in text
        assert "reported pid unknown: owner_unknown" in text


class TestPortCommand:
    def test_inspects_a_port(self) -> None:
        code, out, err = run("port", "5173", built=container(listener(5173, 100)))

        assert code == 0
        assert out.startswith("TCP port 5173")
        assert err == ""

    @pytest.mark.parametrize("argv", [("port",), ("port", "0"), ("port", "65536"), ("port", "x")])
    def test_invalid_ports_are_usage_errors(self, argv: tuple[str, ...]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            run(*argv, built=container())

        assert excinfo.value.code == 2

    def test_no_arguments_lists_the_port_command(self) -> None:
        code, out, _ = run(built=container())

        assert code == 0
        assert "port <port>" in out


def test_owner_observation_type_is_exposed_for_later_slices() -> None:
    inspection = container(listener(5173, 100)).inspect_port.execute(5173)

    assert isinstance(inspection.owners[0].observation, ProcessObservation)
