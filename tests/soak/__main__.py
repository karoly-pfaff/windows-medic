"""``uv run python -m tests.soak``: run the agent for a while and judge its overhead.

Examples::

    uv run python -m tests.soak --minutes 10
    uv run python -m tests.soak --hours 2 --churn --report soak-2h.json
    uv run python -m tests.soak --minutes 30 --config tests/soak/fast-sampling.toml

Exit code 0 when every target holds, 1 otherwise. The report (JSON) is rewritten after
every sample, so an interrupted run still leaves evidence.
"""

import argparse
import sys
import tempfile
import time
from pathlib import Path

from tests.soak.harness import (
    MIB,
    OverheadSample,
    SoakPlan,
    SoakTargets,
    format_summary,
    judge,
    run_soak,
    summarise,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.soak", description=__doc__)
    length = parser.add_mutually_exclusive_group()
    length.add_argument("--minutes", type=float, default=None)
    length.add_argument("--hours", type=float, default=None)
    parser.add_argument("--sample-interval", type=float, default=5.0, metavar="SECONDS")
    parser.add_argument("--data-dir", type=Path, default=None, help="fresh temp dir by default")
    parser.add_argument("--report", type=Path, default=None, help="<data-dir>/soak-report.json")
    parser.add_argument("--config", type=Path, default=None, help="config.toml for the agent")
    parser.add_argument(
        "--churn", action="store_true", help="spawn short-lived processes throughout the run"
    )
    defaults = SoakTargets()
    parser.add_argument("--max-mean-cpu", type=float, default=defaults.max_mean_cpu_percent)
    parser.add_argument(
        "--max-working-set-mib", type=float, default=defaults.max_working_set_bytes / MIB
    )
    arguments = parser.parse_args(argv)

    if arguments.hours is not None:
        duration = arguments.hours * 3600.0
    elif arguments.minutes is not None:
        duration = arguments.minutes * 60.0
    else:
        duration = 300.0
    data_dir = arguments.data_dir or Path(tempfile.mkdtemp(prefix="windows-medic-soak-"))
    plan = SoakPlan(
        duration_seconds=duration,
        sample_interval_seconds=arguments.sample_interval,
        data_dir=data_dir,
        report_path=arguments.report or data_dir / "soak-report.json",
        churn=arguments.churn,
        config_file=arguments.config,
        targets=SoakTargets(
            max_mean_cpu_percent=arguments.max_mean_cpu,
            max_working_set_bytes=int(arguments.max_working_set_mib * MIB),
        ),
    )
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    sys.stdout.write(
        f"[{started}] soaking for {duration:.0f} s in {data_dir} (churn={plan.churn})\n"
    )

    def progress(sample: OverheadSample) -> None:
        sys.stdout.write(
            f"  t+{sample.elapsed_seconds:7.0f}s cpu {sample.agent_cpu_percent:6.3f} % "
            f"ws {sample.working_set_bytes / MIB:6.1f} MiB handles {sample.handles:5d} "
            f"threads {sample.threads:3d} machine {sample.machine_cpu_percent:5.1f} %\n"
        )
        sys.stdout.flush()

    run = run_soak(plan, progress=progress)
    sys.stdout.write(format_summary(run))
    verdict = judge(summarise(run.samples), run.log_summary(), plan.targets)
    return 0 if verdict.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
