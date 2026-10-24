"""GetSystemHealth: two snapshots, exact-identity matching, bounded deterministic contributors."""

from datetime import timedelta

import pytest

from tests.builders import BOOT, GIB, T0, process, process_snapshot, system
from tests.fakes import FakeClock, FakeProcessReader, FakeSystemReader
from windows_medic.application.use_cases.get_system_health import (
    GetSystemHealth,
    HealthLimits,
    SystemHealth,
)
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.samples import DiskIoCounters

WINDOW = 1.0
T1 = T0 + timedelta(seconds=WINDOW)
LIMITS = HealthLimits(measurement_window_seconds=WINDOW, top_contributors=3)


def run(
    *,
    before: FakeProcessReader | None = None,
    after_system: FakeSystemReader | None = None,
    limits: HealthLimits = LIMITS,
) -> tuple[SystemHealth, FakeClock]:
    clock = FakeClock(T0)
    processes = before or FakeProcessReader(process_snapshot(), process_snapshot(observed_at=T1))
    systems = after_system or FakeSystemReader(
        system(observed_at=T0, busy_seconds=1000.0, total_seconds=10_000.0),
        system(observed_at=T1, busy_seconds=1002.0, total_seconds=10_008.0),
    )
    use_case = GetSystemHealth(
        system_reader=systems, process_reader=processes, clock=clock, limits=limits
    )
    return use_case.execute(), clock


class TestSystemMetrics:
    def test_cpu_percent_comes_from_the_delta_between_two_system_snapshots(self) -> None:
        health, _ = run()

        assert health.cpu_percent == 25.0
        assert health.cpu_count == 8

    def test_memory_process_count_and_commit_come_from_the_final_snapshot(self) -> None:
        systems = FakeSystemReader(
            system(observed_at=T0, available_bytes=20 * GIB, process_count=150),
            system(
                observed_at=T1, available_bytes=4 * GIB, process_count=155, total_seconds=10_001.0
            ),
        )

        health, _ = run(after_system=systems)

        assert health.observed_at == T1
        assert health.memory.available_bytes == 4 * GIB
        assert health.memory.percent_used == 87.5
        assert health.process_count == 155
        assert not isinstance(health.commit, Unavailable)
        assert health.commit.percent_used == pytest.approx(41.67, abs=0.01)

    def test_disk_rates_come_from_counter_deltas(self) -> None:
        systems = FakeSystemReader(
            system(observed_at=T0, disk_io=DiskIoCounters(read_bytes=1_000, write_bytes=0)),
            system(
                observed_at=T1,
                total_seconds=10_001.0,
                disk_io=DiskIoCounters(read_bytes=3_000, write_bytes=500),
            ),
        )

        health, _ = run(after_system=systems)

        assert health.disk_read_bytes_per_second == 2_000.0
        assert health.disk_write_bytes_per_second == 500.0

    def test_unavailable_disk_counters_stay_unavailable(self) -> None:
        unsupported = Unavailable(UnavailableReason.NOT_SUPPORTED)
        systems = FakeSystemReader(
            system(observed_at=T0, disk_io=unsupported),
            system(observed_at=T1, total_seconds=10_001.0, disk_io=unsupported),
        )

        health, _ = run(after_system=systems)

        assert health.disk_read_bytes_per_second == unsupported
        assert health.disk_write_bytes_per_second == unsupported

    def test_disk_counters_missing_only_at_baseline_stay_unavailable(self) -> None:
        unsupported = Unavailable(UnavailableReason.NOT_SUPPORTED)
        systems = FakeSystemReader(
            system(observed_at=T0, disk_io=unsupported),
            system(
                observed_at=T1,
                total_seconds=10_001.0,
                disk_io=DiskIoCounters(read_bytes=1, write_bytes=1),
            ),
        )

        health, _ = run(after_system=systems)

        assert health.disk_read_bytes_per_second == unsupported

    def test_waits_the_configured_measurement_window_between_snapshots(self) -> None:
        health, clock = run()

        assert clock.sleeps == [WINDOW]
        assert health.measurement_window_seconds == WINDOW


class TestContributors:
    def test_top_cpu_ranks_matched_identities_by_cpu_over_the_window(self) -> None:
        # cpu_count is 8, window 1 s: 0.8 s of CPU time = 10 % of the machine.
        before = process_snapshot(
            process(10, cpu_time_seconds=5.0),
            process(20, cpu_time_seconds=5.0),
            process(30, cpu_time_seconds=5.0),
            observed_at=T0,
        )
        after = process_snapshot(
            process(10, observed_at=T1, cpu_time_seconds=5.8),
            process(20, observed_at=T1, cpu_time_seconds=8.2),
            process(30, observed_at=T1, cpu_time_seconds=5.0),
            observed_at=T1,
        )

        health, _ = run(before=FakeProcessReader(before, after))

        assert [c.identity.pid for c in health.top_cpu] == [20, 10, 30]
        assert [c.cpu_percent for c in health.top_cpu] == pytest.approx([40.0, 10.0, 0.0])

    def test_top_memory_ranks_by_working_set_from_the_final_snapshot(self) -> None:
        after = process_snapshot(
            process(10, observed_at=T1, working_set_bytes=1 * GIB),
            process(20, observed_at=T1, working_set_bytes=3 * GIB),
            process(30, observed_at=T1, working_set_bytes=2 * GIB),
            observed_at=T1,
        )

        health, _ = run(before=FakeProcessReader(process_snapshot(), after))

        assert [c.identity.pid for c in health.top_memory] == [20, 30, 10]

    def test_contributor_lists_are_bounded_by_the_configured_limit(self) -> None:
        after = process_snapshot(
            *(process(pid, observed_at=T1, working_set_bytes=pid * 1024) for pid in range(1, 20)),
            observed_at=T1,
        )
        limits = HealthLimits(measurement_window_seconds=WINDOW, top_contributors=2)

        health, _ = run(before=FakeProcessReader(process_snapshot(), after), limits=limits)

        assert len(health.top_memory) == 2
        assert len(health.top_cpu) <= 2

    def test_contributors_carry_name_and_memory_alongside_cpu(self) -> None:
        before = process_snapshot(process(10, name="node.exe", cpu_time_seconds=1.0))
        after = process_snapshot(
            process(10, observed_at=T1, name="node.exe", cpu_time_seconds=1.4, private_bytes=7),
            observed_at=T1,
        )

        health, _ = run(before=FakeProcessReader(before, after))

        [contribution] = health.top_cpu
        assert contribution.name == "node.exe"
        assert contribution.cpu_percent == pytest.approx(5.0)
        assert contribution.private_bytes == 7


class TestIdentitySafety:
    def test_reused_pid_never_inherits_the_old_baseline(self) -> None:
        old = process(100, created=BOOT, cpu_time_seconds=500.0, observed_at=T0)
        reused = process(
            100, created=T0 + timedelta(milliseconds=200), cpu_time_seconds=0.1, observed_at=T1
        )

        health, _ = run(
            before=FakeProcessReader(
                process_snapshot(old), process_snapshot(reused, observed_at=T1)
            )
        )

        assert health.top_cpu == ()
        [contribution] = health.top_memory
        assert contribution.identity == reused.identity
        assert contribution.cpu_percent == Unavailable(UnavailableReason.NO_BASELINE)
        assert health.exited_process_count == 1
        assert health.started_process_count == 1

    def test_process_exiting_between_snapshots_does_not_fail_the_measurement(self) -> None:
        before = process_snapshot(
            process(10, cpu_time_seconds=1.0), process(20, cpu_time_seconds=1.0)
        )
        after = process_snapshot(process(20, observed_at=T1, cpu_time_seconds=1.8), observed_at=T1)

        health, _ = run(before=FakeProcessReader(before, after))

        assert [c.identity.pid for c in health.top_cpu] == [20]
        assert health.exited_process_count == 1
        assert health.started_process_count == 0

    def test_skipped_processes_from_collection_are_reported(self) -> None:
        after = process_snapshot(observed_at=T1, skipped_count=3)

        health, _ = run(before=FakeProcessReader(process_snapshot(), after))

        assert health.skipped_process_count == 3


class TestPartialObservations:
    def test_access_denied_cpu_time_is_unavailable_but_memory_still_ranks(self) -> None:
        denied = Unavailable(UnavailableReason.ACCESS_DENIED)
        before = process_snapshot(process(10, cpu_time_seconds=denied))
        after = process_snapshot(
            process(10, observed_at=T1, cpu_time_seconds=denied, working_set_bytes=GIB),
            observed_at=T1,
        )

        health, _ = run(before=FakeProcessReader(before, after))

        assert health.top_cpu == ()
        [contribution] = health.top_memory
        assert contribution.cpu_percent == denied
        assert contribution.working_set_bytes == GIB

    def test_unavailable_memory_is_not_ranked_and_not_faked(self) -> None:
        denied = Unavailable(UnavailableReason.ACCESS_DENIED)
        before = process_snapshot(process(10, cpu_time_seconds=1.0))
        after = process_snapshot(
            process(10, observed_at=T1, cpu_time_seconds=1.8, working_set_bytes=denied),
            observed_at=T1,
        )

        health, _ = run(before=FakeProcessReader(before, after))

        assert health.top_memory == ()
        [contribution] = health.top_cpu
        assert contribution.working_set_bytes == denied

    def test_system_cpu_is_unavailable_when_counters_did_not_advance(self) -> None:
        systems = FakeSystemReader(system(observed_at=T0), system(observed_at=T1))

        health, _ = run(after_system=systems)

        assert health.cpu_percent == Unavailable(UnavailableReason.INCONSISTENT)


class TestLimitsValidation:
    def test_window_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="measurement_window_seconds"):
            HealthLimits(measurement_window_seconds=0.0, top_contributors=1)

    def test_top_contributors_may_not_be_negative(self) -> None:
        with pytest.raises(ValueError, match="top_contributors"):
            HealthLimits(measurement_window_seconds=1.0, top_contributors=-1)
