"""DiagnoseSlowdown against the real machine: bounded, explainable, never raising."""

import io
import logging
import os
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from windows_medic_root.container import compose

pytestmark = pytest.mark.windows_integration

FAST_CONFIG = "[health]\nmeasurement_window_seconds = 0.3\n[diagnosis]\nmax_findings = 6\n"


@pytest.fixture
def root_logger_state() -> Iterator[None]:
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def test_diagnosis_of_the_real_machine_is_bounded_and_explainable(
    root_logger_state: None, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(FAST_CONFIG, encoding="utf-8")
    environ = {
        **os.environ,
        "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data"),
        "WINDOWS_MEDIC_CONFIG_FILE": str(config),
    }
    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)

    diagnosis = container.diagnose_slowdown.execute(timedelta(minutes=10))

    assert diagnosis.lookback[1] - diagnosis.lookback[0] >= timedelta(minutes=10)
    assert diagnosis.incidents == ()  # fresh data directory: the agent never ran here
    assert diagnosis.evidence.processes_observed > 10
    assert len(diagnosis.findings) <= 6
    for finding in diagnosis.findings:
        assert finding.evidence, finding
        assert finding.confidence.factors, finding
        assert len(finding.affected_processes) <= 5
        for candidate in finding.candidate_repairs:
            assert candidate.evidence
            assert candidate.target in {a.identity for a in finding.affected_processes}
