"""The soak harness against the real agent, briefly: it must keep working between releases."""

import json
from pathlib import Path

import pytest

from tests.soak.harness import MIB, SoakPlan, SoakTargets, format_summary, run_soak

pytestmark = pytest.mark.windows_integration


def test_a_short_soak_measures_the_real_agent_and_writes_a_report(tmp_path: Path) -> None:
    plan = SoakPlan(
        duration_seconds=12.0,
        sample_interval_seconds=2.0,
        data_dir=tmp_path / "data",
        report_path=tmp_path / "report.json",
        churn=True,
        targets=SoakTargets(max_mean_cpu_percent=100.0),  # CPU is load-sensitive; not asserted
    )

    run = run_soak(plan)

    assert run.agent_exit_code == 0
    assert len(run.samples) >= 3
    assert all(0 < s.working_set_bytes < 100 * MIB for s in run.samples)
    assert all(s.handles > 0 and s.threads > 0 for s in run.samples)
    assert run.churn_spawned > 0
    log = run.log_summary()
    assert log.final is not None
    assert log.final["system_failures"] == 0
    assert log.final["process_failures"] == 0
    report = json.loads(plan.report_path.read_text("utf-8"))
    assert report["summary"]["sample_count"] == len(run.samples)
    assert report["verdict"]["passed"] is True, report["verdict"]
    assert "verdict: PASS" in format_summary(run)
