"""The soak harness' sampling loop measures only a live agent."""

import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import psutil

from tests.soak.harness import MIB, SoakPlan, SoakRun, _sample_until_exit

if TYPE_CHECKING:
    import subprocess


class RunningLauncher:
    """The launcher is still winding down: ``poll()`` keeps saying it runs."""

    def poll(self) -> int | None:
        return None


class ExitingAgent:
    """Live for the first measurement, then exited (no threads), then gone."""

    def __init__(self) -> None:
        self.measurements = 0

    @contextmanager
    def oneshot(self) -> Iterator[None]:
        yield

    def cpu_percent(self, interval: float | None = None) -> float:
        return 1.0

    def memory_info(self) -> SimpleNamespace:
        return SimpleNamespace(rss=40 * MIB, private=35 * MIB, vms=60 * MIB)

    def num_handles(self) -> int:
        return 180

    def num_threads(self) -> int:
        self.measurements += 1
        if self.measurements > 3:
            raise psutil.NoSuchProcess(4242)
        # An exited process whose handle is still open reports no threads.
        return 9 if self.measurements == 1 else 0


def test_an_agent_that_has_exited_is_not_measured(tmp_path: Path) -> None:
    plan = SoakPlan(
        duration_seconds=1.0,
        sample_interval_seconds=0.01,
        data_dir=tmp_path / "data",
        report_path=tmp_path / "report.json",
    )
    run = SoakRun(plan=plan, started_at=time.monotonic())

    _sample_until_exit(
        run,
        cast("subprocess.Popen[bytes]", RunningLauncher()),
        cast("psutil.Process", ExitingAgent()),
        progress=None,
    )

    assert [s.threads for s in run.samples] == [9]
