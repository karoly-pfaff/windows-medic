"""`windows-medic health`: bounded, readable rendering of SystemHealth at the boundary."""

import io
from collections.abc import Mapping
from dataclasses import replace
from datetime import timedelta
from typing import TextIO

import pytest

from tests.builders import GIB, T0, identity
from tests.containers import fake_container as build_fake_container
from windows_medic.application.use_cases.get_system_health import (
    ProcessContribution,
    SystemHealth,
)
from windows_medic.domain.errors import ObservationError
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.samples import (
    CommitObservation,
    MemoryObservation,
    ProcessSnapshot,
)
from windows_medic_cli import main as cli_main
from windows_medic_cli.render import format_bytes, render_health
from windows_medic_root.container import Container

MIB = 1024**2
T1 = T0 + timedelta(seconds=1)


def health(**overrides: object) -> SystemHealth:
    base = SystemHealth(
        observed_at=T1,
        measurement_window_seconds=1.0,
        cpu_percent=37.5,
        cpu_count=16,
        memory=MemoryObservation(total_bytes=32 * GIB, available_bytes=8 * GIB),
        commit=CommitObservation(limit_bytes=40 * GIB, used_bytes=30 * GIB),
        process_count=312,
        disk_read_bytes_per_second=1.5 * MIB,
        disk_write_bytes_per_second=Unavailable(UnavailableReason.NOT_SUPPORTED),
        top_cpu=(
            ProcessContribution(identity(4242), "node.exe", 25.0, 512 * MIB, 400 * MIB),
            ProcessContribution(
                identity(7), "svchost.exe", 3.26, Unavailable(UnavailableReason.ACCESS_DENIED), 1
            ),
        ),
        top_memory=(ProcessContribution(identity(4242), "node.exe", 25.0, 512 * MIB, 400 * MIB),),
        skipped_process_count=0,
        exited_process_count=2,
        started_process_count=1,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


class TestFormatBytes:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0, "0 B"),
            (1023, "1023 B"),
            (1536, "1.5 KiB"),
            (512 * MIB, "512.0 MiB"),
            (8 * GIB, "8.0 GiB"),
            (3 * 1024 * GIB, "3.0 TiB"),
        ],
    )
    def test_human_readable_binary_units(self, value: int, expected: str) -> None:
        assert format_bytes(value) == expected


class TestRenderHealth:
    def test_headline_facts(self) -> None:
        text = render_health(health())

        assert "measured over 1.0 s" in text
        assert "2026-09-11T12:00:01+00:00" in text
        assert "CPU: 37.5 % of 16 logical processors" in text
        assert "Memory: 24.0 GiB used of 32.0 GiB (75.0 %), 8.0 GiB available" in text
        assert "Commit: 30.0 GiB of 40.0 GiB (75.0 %)" in text
        assert "Processes: 312 (2 exited, 1 started during measurement)" in text
        assert "Disk I/O: read 1.5 MiB/s, write n/a (not_supported)" in text

    def test_contributor_tables_are_rendered_with_explicit_unavailability(self) -> None:
        text = render_health(health())
        lines = text.splitlines()

        top_cpu = lines.index("Top CPU")
        assert lines[top_cpu + 1].split() == ["PID", "CPU%", "Working", "set", "Name"]
        assert lines[top_cpu + 2].split() == ["4242", "25.0", "512.0", "MiB", "node.exe"]
        assert lines[top_cpu + 3].split() == ["7", "3.3", "n/a", "(access_denied)", "svchost.exe"]
        assert "Top memory" in text

    def test_unavailable_system_metrics_are_explicit(self) -> None:
        text = render_health(
            health(
                cpu_percent=Unavailable(UnavailableReason.INCONSISTENT),
                commit=Unavailable(UnavailableReason.ERROR),
            )
        )

        assert "CPU: n/a (inconsistent)" in text
        assert "Commit: n/a (error)" in text

    def test_empty_contributor_lists_say_so(self) -> None:
        text = render_health(health(top_cpu=(), top_memory=()))

        assert "Top CPU\n  (no contributors with an available measurement)" in text


def fake_container(*, failing: bool = False) -> Container:
    return build_fake_container(process_reader=_FailingProcessReader() if failing else None)


class _FailingProcessReader:
    def snapshot(self) -> ProcessSnapshot:
        raise ObservationError("process enumeration failed: NTSTATUS 0xC0000005")

    def get(self, identity: ProcessIdentity) -> ProcessObservation | None:
        return None


def _composer(container: Container | None) -> cli_main.Composer:
    def compose(
        program: str, *, environ: Mapping[str, str], log_stream: TextIO, error_stream: TextIO
    ) -> Container | None:
        if container is None:
            error_stream.write(f"{program}: configuration error\nbroken\n")
        return container

    return compose


class TestHealthCommand:
    def test_prints_rendered_health_and_exits_zero(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()

        code = cli_main.main(
            ["health"],
            environ={},
            stdout=stdout,
            stderr=stderr,
            compose=_composer(fake_container()),
        )

        assert code == 0
        assert "CPU: 25.0 % of 8 logical processors" in stdout.getvalue()
        assert "node.exe" in stdout.getvalue()

    def test_configuration_error_exits_with_code_2(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()

        code = cli_main.main(
            ["health"], environ={}, stdout=stdout, stderr=stderr, compose=_composer(None)
        )

        assert code == 2
        assert stdout.getvalue() == ""
        assert "configuration error" in stderr.getvalue()

    def test_observation_failure_is_reported_without_a_traceback(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()

        code = cli_main.main(
            ["health"],
            environ={},
            stdout=stdout,
            stderr=stderr,
            compose=_composer(fake_container(failing=True)),
        )

        assert code == 1
        assert stdout.getvalue() == ""
        assert (
            stderr.getvalue() == "windows-medic: process enumeration failed: NTSTATUS 0xC0000005\n"
        )

    def test_no_arguments_lists_available_commands(self) -> None:
        stdout = io.StringIO()

        code = cli_main.main(
            [], environ={}, stdout=stdout, stderr=io.StringIO(), compose=_composer(fake_container())
        )

        assert code == 0
        assert "health" in stdout.getvalue()
