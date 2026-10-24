"""The soak harness' judgement is pure: samples in, verdict out."""

import json

from tests.soak.harness import (
    MIB,
    AgentLogSummary,
    OverheadSample,
    SoakTargets,
    judge,
    summarise,
    summarise_log,
)


def sample(
    elapsed: float,
    *,
    cpu: float = 0.3,
    working_set: int = 40 * MIB,
    handles: int = 200,
    threads: int = 8,
) -> OverheadSample:
    return OverheadSample(
        elapsed_seconds=elapsed,
        agent_cpu_percent=cpu,
        agent_cpu_percent_one_core=cpu * 8,
        machine_cpu_percent=12.0,
        working_set_bytes=working_set,
        private_bytes=working_set - 5 * MIB,
        handles=handles,
        threads=threads,
    )


def health(**fields: object) -> str:
    record: dict[str, object] = {
        "ts": "2026-09-11T12:00:00Z",
        "level": "INFO",
        "event": "agent.health",
        "system_failures": 0,
        "process_failures": 0,
        "overruns": 0,
        "incidents_opened": 0,
        "incident_persist_failures": 0,
        "system_samples_held": 900,
        "process_snapshots_held": 180,
    }
    record.update(fields)
    return json.dumps(record)


class TestSummarise:
    def test_quarters_and_growth(self) -> None:
        samples = [sample(float(i), working_set=(40 + i) * MIB, handles=200 + i) for i in range(8)]

        summary = summarise(samples)

        assert summary.sample_count == 8
        assert summary.duration_seconds == 7.0
        assert summary.mean_cpu_percent == 0.3
        assert summary.max_cpu_percent == 0.3
        assert summary.first_quarter_working_set_bytes == 40.5 * MIB
        assert summary.last_quarter_working_set_bytes == 46.5 * MIB
        assert summary.working_set_growth_bytes == 6 * MIB
        assert summary.max_working_set_bytes == 47 * MIB
        assert summary.handle_growth == 6
        assert summary.thread_growth == 0

    def test_a_single_sample_is_its_own_quarters(self) -> None:
        summary = summarise([sample(0.0)])

        assert summary.working_set_growth_bytes == 0
        assert summary.p95_cpu_percent == 0.3

    def test_p95_takes_the_upper_tail(self) -> None:
        samples = [sample(float(i), cpu=float(i)) for i in range(100)]

        assert summarise(samples).p95_cpu_percent == 95.0


class TestJudge:
    def test_a_quiet_agent_passes_every_target(self) -> None:
        summary = summarise([sample(float(i)) for i in range(20)])
        log = summarise_log([health()])

        verdict = judge(summary, log, SoakTargets())

        assert verdict.passed is True
        assert verdict.findings == ()

    def test_each_target_names_its_breach(self) -> None:
        samples = [
            sample(
                float(i),
                cpu=2.5,
                working_set=(90 + i * 2) * MIB,
                handles=100 + i * 20,
                threads=8 + i,
            )
            for i in range(20)
        ]
        log = summarise_log([health(system_failures=1, overruns=3, incident_persist_failures=2)])

        verdict = judge(summarise(samples), log, SoakTargets())

        assert verdict.passed is False
        joined = "\n".join(verdict.findings)
        assert "mean agent CPU 2.50 % exceeds 1.00 %" in joined
        assert "working set" in joined
        assert "grew" in joined
        assert "handles grew by" in joined
        assert "threads grew by" in joined
        assert "collector failures: system 1" in joined
        assert "persist failures: 2" in joined
        assert "overruns: 3" in joined

    def test_no_samples_is_a_failure_not_a_pass(self) -> None:
        verdict = judge(summarise([]), summarise_log([]), SoakTargets())

        assert verdict.passed is False
        assert "no samples" in verdict.findings[0]
        assert "no agent.health" in verdict.findings[1]


class TestSummariseLog:
    def test_counts_events_and_keeps_the_last_health_record(self) -> None:
        lines = [
            json.dumps({"event": "config.loaded"}),
            health(uptime_seconds=5),
            json.dumps({"event": "sampler.overrun", "sampler": "process"}),
            json.dumps({"event": "collector.failed", "sampler": "system"}),
            json.dumps({"event": "incident.opened"}),
            "not json at all",
            health(uptime_seconds=10, incidents_opened=1),
            json.dumps(
                {
                    "event": "agent.monitor.stopped",
                    "incidents_opened": 1,
                    "system_failures": 0,
                    "process_failures": 0,
                    "overruns": 1,
                    "incident_persist_failures": 0,
                }
            ),
        ]

        summary = summarise_log(lines)

        assert summary.health_records == 2
        assert summary.last_health is not None
        assert summary.last_health["uptime_seconds"] == 10
        assert summary.final is not None
        assert summary.final["overruns"] == 1
        assert summary.events["sampler.overrun"] == 1
        assert summary.events["collector.failed"] == 1
        assert summary.events["incident.opened"] == 1
        assert summary.unparseable_lines == 1
        assert isinstance(summary, AgentLogSummary)
