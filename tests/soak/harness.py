"""Measure the real agent from outside and judge it against the product's targets.

The agent is started as the installed console script (launcher plus interpreter) against
its own data directory; every ``sample_interval`` seconds the interpreter's CPU share,
working set, private bytes, handles and threads are recorded with psutil. The agent's own
``agent.health`` records are read from its log file. The verdict is a pure function of
those two series so the judgement can be unit-tested without a soak.
"""

import json
import math
import os
import statistics
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

import psutil

from tests.soak.stress import ProcessChurn, wait_until

MIB = 1024 * 1024
_COUNTED_EVENTS = (
    "sampler.overrun",
    "collector.failed",
    "collector.crashed",
    "incident.opened",
    "incident.closed",
    "incident.persist_failed",
    "sampling.mode_changed",
)


@dataclass(frozen=True, slots=True)
class OverheadSample:
    elapsed_seconds: float
    agent_cpu_percent: float
    """Share of the whole machine (one core fully busy on an 8-core box is 12.5 %)."""
    agent_cpu_percent_one_core: float
    machine_cpu_percent: float
    working_set_bytes: int
    private_bytes: int
    handles: int
    threads: int


@dataclass(frozen=True, slots=True)
class SoakTargets:
    """Product-spec §14 targets plus growth bounds that make "bounded" checkable."""

    max_mean_cpu_percent: float = 1.0
    max_working_set_bytes: int = 100 * MIB
    max_working_set_growth_bytes: int = 16 * MIB
    max_handle_growth: int = 100
    max_thread_growth: int = 4


@dataclass(frozen=True, slots=True)
class SoakSummary:
    sample_count: int
    duration_seconds: float
    mean_cpu_percent: float
    p95_cpu_percent: float
    max_cpu_percent: float
    mean_machine_cpu_percent: float
    first_quarter_working_set_bytes: float
    last_quarter_working_set_bytes: float
    working_set_growth_bytes: float
    max_working_set_bytes: int
    max_private_bytes: int
    handle_growth: int
    max_handles: int
    thread_growth: int
    max_threads: int


@dataclass(frozen=True, slots=True)
class AgentLogSummary:
    health_records: int
    last_health: dict[str, object] | None
    final: dict[str, object] | None
    events: dict[str, int]
    unparseable_lines: int


@dataclass(frozen=True, slots=True)
class Verdict:
    passed: bool
    findings: tuple[str, ...]


def _quarter_means(values: Sequence[float]) -> tuple[float, float]:
    quarter = max(1, len(values) // 4)
    return statistics.fmean(values[:quarter]), statistics.fmean(values[-quarter:])


def _p95(values: Sequence[float]) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(0.95 * (len(ordered) - 1)))]


def summarise(samples: Sequence[OverheadSample]) -> SoakSummary:
    if not samples:
        return SoakSummary(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0, 0, 0, 0)
    cpu = [s.agent_cpu_percent for s in samples]
    working_set = [float(s.working_set_bytes) for s in samples]
    first_ws, last_ws = _quarter_means(working_set)
    first_handles, last_handles = _quarter_means([float(s.handles) for s in samples])
    first_threads, last_threads = _quarter_means([float(s.threads) for s in samples])
    return SoakSummary(
        sample_count=len(samples),
        duration_seconds=samples[-1].elapsed_seconds - samples[0].elapsed_seconds,
        mean_cpu_percent=statistics.fmean(cpu),
        p95_cpu_percent=_p95(cpu),
        max_cpu_percent=max(cpu),
        mean_machine_cpu_percent=statistics.fmean(s.machine_cpu_percent for s in samples),
        first_quarter_working_set_bytes=first_ws,
        last_quarter_working_set_bytes=last_ws,
        working_set_growth_bytes=last_ws - first_ws,
        max_working_set_bytes=max(s.working_set_bytes for s in samples),
        max_private_bytes=max(s.private_bytes for s in samples),
        handle_growth=round(last_handles - first_handles),
        max_handles=max(s.handles for s in samples),
        thread_growth=round(last_threads - first_threads),
        max_threads=max(s.threads for s in samples),
    )


def summarise_log(lines: Iterable[str]) -> AgentLogSummary:
    counts: Counter[str] = Counter()
    last_health: dict[str, object] | None = None
    final: dict[str, object] | None = None
    health_records = 0
    unparseable = 0
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            unparseable += 1
            continue
        if not isinstance(record, dict):
            unparseable += 1
            continue
        event = record.get("event")
        if event == "agent.health":
            health_records += 1
            last_health = record
        elif event == "agent.monitor.stopped":
            final = record
        elif event in _COUNTED_EVENTS:
            counts[str(event)] += 1
    return AgentLogSummary(
        health_records=health_records,
        last_health=last_health,
        final=final,
        events={name: counts[name] for name in _COUNTED_EVENTS},
        unparseable_lines=unparseable,
    )


def _as_int(record: Mapping[str, object] | None, key: str) -> int:
    value = record.get(key) if record is not None else None
    return value if isinstance(value, int) else 0


def _resource_findings(summary: SoakSummary, targets: SoakTargets) -> list[str]:
    if summary.sample_count == 0:
        return ["no samples were taken"]
    findings: list[str] = []
    if summary.mean_cpu_percent > targets.max_mean_cpu_percent:
        findings.append(
            f"mean agent CPU {summary.mean_cpu_percent:.2f} % exceeds "
            f"{targets.max_mean_cpu_percent:.2f} % (p95 {summary.p95_cpu_percent:.2f} %, "
            f"max {summary.max_cpu_percent:.2f} %)"
        )
    if summary.max_working_set_bytes > targets.max_working_set_bytes:
        findings.append(
            f"max working set {summary.max_working_set_bytes / MIB:.1f} MiB exceeds "
            f"{targets.max_working_set_bytes / MIB:.0f} MiB"
        )
    if summary.working_set_growth_bytes > targets.max_working_set_growth_bytes:
        findings.append(
            f"working set grew by {summary.working_set_growth_bytes / MIB:.1f} MiB between the "
            f"first and last quarter (limit {targets.max_working_set_growth_bytes / MIB:.0f} MiB)"
        )
    if summary.handle_growth > targets.max_handle_growth:
        findings.append(
            f"handles grew by {summary.handle_growth} (limit {targets.max_handle_growth})"
        )
    if summary.thread_growth > targets.max_thread_growth:
        findings.append(
            f"threads grew by {summary.thread_growth} (limit {targets.max_thread_growth})"
        )
    return findings


def _log_findings(log: AgentLogSummary) -> list[str]:
    final = log.final if log.final is not None else log.last_health
    if final is None:
        return ["no agent.health record was found in the agent log"]
    findings: list[str] = []
    system_failures = _as_int(final, "system_failures")
    process_failures = _as_int(final, "process_failures")
    if system_failures or process_failures:
        findings.append(f"collector failures: system {system_failures}, process {process_failures}")
    persist_failures = _as_int(final, "incident_persist_failures")
    if persist_failures:
        findings.append(f"incident persist failures: {persist_failures}")
    overruns = _as_int(final, "overruns")
    if overruns:
        findings.append(f"sampler overruns: {overruns}")
    if log.events.get("collector.crashed", 0):
        findings.append(f"collector crashes: {log.events['collector.crashed']}")
    return findings


def judge(summary: SoakSummary, log: AgentLogSummary, targets: SoakTargets) -> Verdict:
    findings = [*_resource_findings(summary, targets), *_log_findings(log)]
    return Verdict(passed=not findings, findings=tuple(findings))


# -- running the real agent ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SoakPlan:
    duration_seconds: float
    sample_interval_seconds: float
    data_dir: Path
    report_path: Path
    churn: bool = False
    config_file: Path | None = None
    targets: SoakTargets = field(default_factory=SoakTargets)


@dataclass(slots=True)
class SoakRun:
    plan: SoakPlan
    started_at: float
    samples: list[OverheadSample] = field(default_factory=list)
    agent_exit_code: int | None = None
    churn_spawned: int = 0

    @property
    def log_file(self) -> Path:
        return self.plan.data_dir / "logs" / "windows-medic-agent.log"

    def log_summary(self) -> AgentLogSummary:
        if not self.log_file.exists():
            return summarise_log([])
        return summarise_log(self.log_file.read_text("utf-8").splitlines())

    def report(self) -> dict[str, object]:
        summary = summarise(self.samples)
        log = self.log_summary()
        verdict = judge(summary, log, self.plan.targets)
        return {
            "plan": {
                "duration_seconds": self.plan.duration_seconds,
                "sample_interval_seconds": self.plan.sample_interval_seconds,
                "data_dir": str(self.plan.data_dir),
                "churn": self.plan.churn,
                "config_file": None
                if self.plan.config_file is None
                else str(self.plan.config_file),
                "targets": asdict(self.plan.targets),
            },
            "machine": {
                "cpu_count": psutil.cpu_count(logical=True),
                "total_memory_bytes": psutil.virtual_memory().total,
                "python": sys.version.split()[0],
            },
            "agent_exit_code": self.agent_exit_code,
            "churn_spawned": self.churn_spawned,
            "summary": asdict(summary),
            "agent_log": asdict(log),
            "verdict": asdict(verdict),
            "samples": [asdict(s) for s in self.samples],
        }

    def write_report(self) -> None:
        self.plan.report_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.plan.report_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.report(), indent=2), encoding="utf-8")
        temporary.replace(self.plan.report_path)


def agent_executable() -> Path:
    return Path(sys.executable).parent / "windows-medic-agent.exe"


def agent_pid_from_log(log_file: Path) -> int | None:
    """The PID the agent logged in ``agent.started``.

    The console script is a chain of launchers (uv trampoline, venv ``python.exe``) ending
    in the real interpreter; the log is the only exact way to find the last one.
    """
    if not log_file.exists():
        return None
    for line in log_file.read_text("utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("event") == "agent.started":
            pid = record.get("pid")
            return pid if isinstance(pid, int) else None
    return None


def _measure(agent: psutil.Process, elapsed: float, cpu_count: int) -> OverheadSample:
    with agent.oneshot():
        one_core = agent.cpu_percent(interval=None)
        memory = agent.memory_info()
        handles = agent.num_handles()
        threads = agent.num_threads()
    return OverheadSample(
        elapsed_seconds=round(elapsed, 1),
        agent_cpu_percent=round(one_core / cpu_count, 3),
        agent_cpu_percent_one_core=round(one_core, 2),
        machine_cpu_percent=psutil.cpu_percent(interval=None),
        working_set_bytes=memory.rss,
        private_bytes=getattr(memory, "private", memory.vms),
        handles=handles,
        threads=threads,
    )


def _start_agent(plan: SoakPlan, env: dict[str, str], log_file: Path) -> subprocess.Popen[bytes]:
    command = [
        str(agent_executable()),
        "--duration",
        str(plan.duration_seconds),
        "--log-file",
        str(log_file),
    ]
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )


def _await_agent(launcher: subprocess.Popen[bytes], log_file: Path) -> psutil.Process:
    found: list[int] = []

    def started_or_gone() -> bool:
        pid = agent_pid_from_log(log_file)
        if pid is not None:
            found.append(pid)
        return pid is not None or launcher.poll() is not None

    wait_until(started_or_gone, deadline_seconds=30)
    if not found:
        exit_code = launcher.poll()
        raise RuntimeError(
            "the agent did not log agent.started"
            + ("" if exit_code is None else f" (it exited with code {exit_code})")
        )
    return psutil.Process(found[0])


def _kill_tree(launcher: psutil.Process) -> None:
    for member in [launcher, *launcher.children(recursive=True)]:
        try:
            member.kill()
        except psutil.NoSuchProcess:
            continue


def _sample_until_exit(
    run: SoakRun,
    launcher: subprocess.Popen[bytes],
    agent: psutil.Process,
    progress: Callable[[OverheadSample], None] | None,
) -> None:
    plan = run.plan
    cpu_count = psutil.cpu_count(logical=True) or 1
    agent.cpu_percent(interval=None)  # prime: the next call measures from now
    psutil.cpu_percent(interval=None)
    next_sample = time.monotonic() + plan.sample_interval_seconds
    while launcher.poll() is None:
        now = time.monotonic()
        if now >= next_sample:
            next_sample += plan.sample_interval_seconds
            try:
                sample = _measure(agent, now - run.started_at, cpu_count)
            except psutil.NoSuchProcess:
                return
            if sample.threads == 0:
                # The interpreter has exited (a live process always has a thread) while
                # the launcher is still winding down: the run is over, not a measurement.
                return
            run.samples.append(sample)
            if progress is not None:
                progress(sample)
            run.write_report()
        time.sleep(min(0.5, max(0.05, next_sample - time.monotonic())))


def run_soak(
    plan: SoakPlan,
    *,
    environ: Mapping[str, str] | None = None,
    progress: Callable[[OverheadSample], None] | None = None,
) -> SoakRun:
    """Run the agent for ``plan.duration_seconds`` and sample it.

    The report is rewritten after every sample so a partial run still leaves evidence.
    """
    env = dict(os.environ if environ is None else environ)
    env["WINDOWS_MEDIC_DATA_DIR"] = str(plan.data_dir)
    if plan.config_file is not None:
        env["WINDOWS_MEDIC_CONFIG_FILE"] = str(plan.config_file)
    run = SoakRun(plan=plan, started_at=time.monotonic())
    launcher = _start_agent(plan, env, run.log_file)
    launcher_process = psutil.Process(launcher.pid)
    churn = ProcessChurn(batch=4, pause_seconds=0.5) if plan.churn else None
    try:
        agent = _await_agent(launcher, run.log_file)
        if churn is not None:
            churn.__enter__()
        _sample_until_exit(run, launcher, agent, progress)
        run.agent_exit_code = launcher.wait(timeout=60)
    finally:
        if churn is not None:
            churn.__exit__(None, None, None)
            run.churn_spawned = churn.counter.spawned
        if launcher.poll() is None:
            _kill_tree(launcher_process)
            launcher.wait(timeout=60)
        run.write_report()
    return run


def format_summary(run: SoakRun) -> str:
    report = run.report()
    summary = report["summary"]
    verdict = report["verdict"]
    assert isinstance(summary, dict)
    assert isinstance(verdict, dict)
    log = report["agent_log"]
    assert isinstance(log, dict)
    lines = [
        (
            f"Soak: {summary['sample_count']} samples over {summary['duration_seconds']:.0f} s, "
            f"agent exit code {run.agent_exit_code}"
        ),
        (
            f"  agent CPU (machine share): mean {summary['mean_cpu_percent']:.3f} %, "
            f"p95 {summary['p95_cpu_percent']:.3f} %, max {summary['max_cpu_percent']:.3f} % "
            f"(machine mean {summary['mean_machine_cpu_percent']:.1f} %)"
        ),
        (
            f"  working set: first quarter "
            f"{summary['first_quarter_working_set_bytes'] / MIB:.1f} MiB, "
            f"last quarter {summary['last_quarter_working_set_bytes'] / MIB:.1f} MiB, "
            f"max {summary['max_working_set_bytes'] / MIB:.1f} MiB "
            f"(private max {summary['max_private_bytes'] / MIB:.1f} MiB)"
        ),
        (
            f"  handles max {summary['max_handles']} (growth {summary['handle_growth']}), "
            f"threads max {summary['max_threads']} (growth {summary['thread_growth']})"
        ),
        f"  agent log events: {json.dumps(log['events'])}",
        "  verdict: " + ("PASS" if verdict["passed"] else "FAIL"),
    ]
    lines.extend(f"    - {finding}" for finding in verdict["findings"])
    lines.append(f"  report: {run.plan.report_path}")
    return "\n".join(lines) + "\n"
