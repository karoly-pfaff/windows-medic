"""`windows-medic incidents`: bounded, newest-first summaries for developer verification."""

import io
from collections.abc import Mapping
from datetime import timedelta
from typing import TextIO

import pytest

from tests.builders import T0
from tests.containers import fake_container
from tests.fakes import FakeIncidentRepository
from windows_medic.domain.errors import IncidentStoreError
from windows_medic.domain.models.incident import (
    EvidenceLimits,
    IncidentKind,
    IncidentSummary,
    begin_recovery,
    close_incident,
    open_incident,
    summarise,
)
from windows_medic_cli import main as cli_main
from windows_medic_cli.render import render_incidents
from windows_medic_root.container import Container

LIMITS = EvidenceLimits(
    max_system_samples=5, max_contributors=2, high_severity_after=timedelta(seconds=120)
)


def repository_with(count: int) -> FakeIncidentRepository:
    repository = FakeIncidentRepository()
    for number in range(count):
        started = T0 + timedelta(minutes=number)
        incident = open_incident(
            incident_id=f"inc-{number}",
            kind=IncidentKind.CPU_PRESSURE if number % 2 == 0 else IncidentKind.MEMORY_PRESSURE,
            started_at=started,
            triggered_at=started + timedelta(seconds=20),
            threshold=90.0,
            pre_trigger=(),
            contributors=(),
            evidence_window=(started - timedelta(minutes=1), started),
            limits=LIMITS,
        )
        if number == 0:
            incident = close_incident(
                begin_recovery(incident, started + timedelta(seconds=200)),
                started + timedelta(seconds=230),
                LIMITS,
            )
        repository.save(incident)
    return repository


class BrokenRepository(FakeIncidentRepository):
    def recent(self, *, limit: int) -> tuple[IncidentSummary, ...]:
        raise IncidentStoreError("database is locked")


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


class TestRender:
    def test_table_is_newest_first_with_status_severity_and_duration(self) -> None:
        built = fake_container(incident_repository=repository_with(3))
        summaries = built.list_recent_incidents.execute()

        text = render_incidents(summaries)
        lines = text.splitlines()

        assert lines[0] == "Recent incidents: 3 (newest first)"
        assert lines[1].split() == [
            "ID",
            "Kind",
            "Status",
            "Severity",
            "Started",
            "Duration",
            "Peak",
        ]
        assert lines[2].split()[:4] == ["inc-2", "cpu_pressure", "open", "medium"]
        assert lines[4].split()[:4] == ["inc-0", "cpu_pressure", "closed", "high"]
        assert "3m50s" in lines[4]
        assert lines[2].endswith("90.0")

    def test_empty(self) -> None:
        assert render_incidents(()) == "No incidents recorded.\n"

    def test_durations_over_an_hour_show_hours(self) -> None:
        started = T0 + timedelta(minutes=1)
        incident = repository_with(2).incidents["inc-1"]
        closed = close_incident(
            begin_recovery(incident, started + timedelta(hours=1)),
            started + timedelta(hours=1, minutes=2, seconds=3),
            LIMITS,
        )

        assert "1h02m03s" in render_incidents((summarise(closed),))


class TestCommand:
    def test_lists_incidents(self) -> None:
        built = fake_container(incident_repository=repository_with(2))

        code, out, err = run("incidents", built=built)

        assert code == 0
        assert out.startswith("Recent incidents: 2")
        assert err == ""

    def test_limit_option(self) -> None:
        built = fake_container(incident_repository=repository_with(3))

        code, out, _ = run("incidents", "--limit", "1", built=built)

        assert code == 0
        assert "Recent incidents: 1" in out
        assert "inc-2" in out

    @pytest.mark.parametrize("value", ["0", "-3", "many"])
    def test_invalid_limit_is_a_usage_error(self, value: str) -> None:
        with pytest.raises(SystemExit) as excinfo:
            run("incidents", "--limit", value, built=fake_container())

        assert excinfo.value.code == 2

    def test_store_failure_is_reported_without_a_traceback(self) -> None:
        built = fake_container(incident_repository=BrokenRepository())

        code, out, err = run("incidents", built=built)

        assert code == 1
        assert out == ""
        assert err == "windows-medic: database is locked\n"

    def test_no_arguments_lists_the_incidents_command(self) -> None:
        code, out, _ = run(built=fake_container())

        assert code == 0
        assert "incidents" in out
