"""`windows-medic diagnose`: bounded, readable rendering of a Diagnosis at the boundary."""

import io
from collections.abc import Mapping
from datetime import timedelta
from typing import TextIO

import pytest

from tests.builders import T0, contributor, incident, process, process_snapshot
from tests.containers import fake_container
from tests.fakes import FakeHungWindowReader, FakeIncidentRepository, FakeProcessReader
from windows_medic.domain.errors import IncidentStoreError
from windows_medic.domain.models.gui import HungWindow
from windows_medic.domain.models.incident import Incident
from windows_medic_cli import main as cli_main
from windows_medic_cli.render import render_diagnosis
from windows_medic_root.container import Container

T1 = T0 + timedelta(seconds=1)
OLD = T0 - timedelta(hours=2)


class BrokenRepository(FakeIncidentRepository):
    def active_since(self, cutoff: object, *, limit: int) -> tuple[Incident, ...]:
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


def busy_container() -> Container:
    """A calm current sample, one past incident, an orphaned dev tree and a hung window."""
    repository = FakeIncidentRepository()
    repository.save(
        incident(
            "inc-1234abcd",
            started_at=T0 - timedelta(minutes=5),
            contributors=(contributor(100, name="build.exe", cpu_percent=60.0),),
        )
    )
    before = process_snapshot(
        process(4, name="explorer.exe"),
        process(10, name="node.exe", created=OLD, parent_pid=777),
        process(11, name="esbuild.exe", created=OLD, parent_pid=10),
        process(30, name="app.exe"),
    )
    after = process_snapshot(
        process(4, name="explorer.exe", observed_at=T1),
        process(10, name="node.exe", created=OLD, parent_pid=777, observed_at=T1),
        process(11, name="esbuild.exe", created=OLD, parent_pid=10, observed_at=T1),
        process(30, name="app.exe", observed_at=T1),
        observed_at=T1,
    )
    return fake_container(
        process_reader=FakeProcessReader(before, after),
        incident_repository=repository,
        hung_window_reader=FakeHungWindowReader(HungWindow(30, "Editor")),
    )


def calm_container() -> Container:
    return fake_container(
        process_reader=FakeProcessReader(
            process_snapshot(process(4, name="explorer.exe")),
            process_snapshot(process(4, name="explorer.exe", observed_at=T1), observed_at=T1),
        )
    )


class TestRender:
    def test_report_is_ranked_bounded_and_names_evidence_and_confidence(self) -> None:
        built = busy_container()
        diagnosis = built.diagnose_slowdown.execute()

        text = render_diagnosis(diagnosis)
        lines = text.splitlines()

        assert lines[0] == (
            "Slowdown diagnosis: last 30 min, measured at 2026-09-11T12:00:01+00:00 over 1.0 s"
        )
        assert lines[1].startswith("Now: CPU 25.0 % of 8 logical processors, memory 50.0 % used")
        assert "Incidents in window: 1 (newest first)" in text
        assert "inc-1234abcd cpu_pressure closed high" in " ".join(text.split())
        assert "Evidence considered: 1 incident, 1 system sample, 1 contributor sample; " in text
        assert "4 processes observed; 1 hung window (0 unverified)" in text
        assert "Findings: 4 (ranked)" in text
        findings_start = lines.index("Findings: 4 (ranked)")
        headings = [line for line in lines[findings_start:] if line[:2] in ("1.", "2.", "3.", "4.")]
        assert headings == [
            "1. cpu_pressure [severity high, confidence medium]",
            "2. resource_hog [severity high, confidence medium]",
            "3. hung_gui [severity medium, confidence high]",
            "4. suspected_stale_dev_tree [severity low, confidence high]",
        ]
        assert "   confidence raised by: sustained_incident; lowered by: -" in text
        assert "   confidence raised by: hung_window_reported; lowered by: -" in text
        assert "     - window 'Editor' is not responding" in text
        assert "   processes: app.exe (pid 30 @ 2026-09-11T09:00:00+00:00) protection none" in text
        assert "   candidate repairs:" in text
        assert (
            "     - process.terminate pid 30 @ 2026-09-11T09:00:00+00:00: risk low, eligible"
        ) in text
        assert (
            "     - process.terminate_tree pid 10 @ 2026-09-11T10:00:00+00:00: risk low, eligible"
        ) in text
        assert "   processes: build.exe (pid 100 @ 2026-09-11T09:00:00+00:00, exited)" in text
        assert "   candidate repairs: none" in text

    def test_blocked_candidates_show_their_blockers(self) -> None:
        built = fake_container(
            process_reader=FakeProcessReader(
                process_snapshot(process(4, name="explorer.exe")),
                process_snapshot(process(4, name="explorer.exe", observed_at=T1), observed_at=T1),
            ),
            hung_window_reader=FakeHungWindowReader(HungWindow(4, "")),
        )

        text = render_diagnosis(built.diagnose_slowdown.execute())

        assert (
            "     - process.terminate pid 4 @ 2026-09-11T09:00:00+00:00: risk high, "
            "blocked by target_protected"
        ) in text

    def test_nothing_found_is_said_with_the_evidence_that_was_considered(self) -> None:
        built = calm_container()

        text = render_diagnosis(built.diagnose_slowdown.execute())

        assert "Incidents in window: 0" in text
        assert "Findings: none" in text
        assert "Evidence considered: 0 incidents" in text


class TestCommand:
    def test_diagnose_command_renders_the_report(self) -> None:
        code, out, err = run("diagnose", built=busy_container())

        assert code == 0
        assert out.startswith("Slowdown diagnosis: last 30 min")
        assert err == ""

    def test_since_minutes_option_sets_the_lookback(self) -> None:
        code, out, _ = run("diagnose", "--since-minutes", "90", built=busy_container())

        assert code == 0
        assert out.startswith("Slowdown diagnosis: last 1 h 30 min")

    @pytest.mark.parametrize("value", ["0", "-5", "soon"])
    def test_invalid_lookback_is_a_usage_error(self, value: str) -> None:
        with pytest.raises(SystemExit) as excinfo:
            run("diagnose", "--since-minutes", value, built=calm_container())

        assert excinfo.value.code == 2

    def test_lookback_beyond_the_configured_maximum_is_a_usage_error(self) -> None:
        code, out, err = run("diagnose", "--since-minutes", "100000", built=calm_container())

        assert code == 2
        assert out == ""
        assert err == "windows-medic: --since-minutes must be between 1 and 240\n"

    def test_store_failure_is_reported_without_a_traceback(self) -> None:
        built = fake_container(
            process_reader=FakeProcessReader(
                process_snapshot(process(4, name="explorer.exe")),
                process_snapshot(process(4, name="explorer.exe", observed_at=T1), observed_at=T1),
            ),
            incident_repository=BrokenRepository(),
        )

        code, out, err = run("diagnose", built=built)

        assert code == 1
        assert out == ""
        assert err == "windows-medic: database is locked\n"

    def test_no_arguments_lists_the_diagnose_command(self) -> None:
        code, out, _ = run(built=calm_container())

        assert code == 0
        assert "diagnose" in out
