"""Build the monitor from the composed container and typed settings."""

import os
from datetime import timedelta

from windows_medic.domain.models.incident import EvidenceLimits
from windows_medic.domain.policies.adaptive_sampling import AdaptivePolicy
from windows_medic.domain.policies.pressure_lifecycle import LifecyclePolicy
from windows_medic_agent.evidence import EvidenceRetention, RollingEvidence
from windows_medic_agent.incident_engine import IncidentEngine, IncidentPolicy
from windows_medic_agent.monitor import Monitor, SamplingIntervals
from windows_medic_root.container import Container


def build_monitor(container: Container) -> Monitor:
    settings = container.settings
    evidence = RollingEvidence(
        EvidenceRetention(
            window=timedelta(minutes=settings.history.rolling_window_minutes),
            max_system_samples=settings.history.max_system_samples,
            max_process_snapshots=settings.history.max_process_snapshots,
        )
    )
    thresholds = container.pressure_thresholds
    incidents = settings.incidents
    recovery = timedelta(seconds=incidents.recovery_seconds)
    engine = IncidentEngine(
        repository=container.incident_repository,
        evidence=evidence,
        policy=IncidentPolicy(
            thresholds=thresholds,
            cpu_lifecycle=LifecyclePolicy(
                duration=timedelta(seconds=settings.pressure.cpu_duration_seconds),
                recovery=recovery,
            ),
            memory_lifecycle=LifecyclePolicy(
                duration=timedelta(seconds=settings.pressure.memory_duration_seconds),
                recovery=recovery,
            ),
            evidence=EvidenceLimits(
                max_system_samples=incidents.max_system_samples,
                max_contributors=incidents.max_contributors,
                high_severity_after=timedelta(seconds=incidents.high_severity_after_seconds),
            ),
            pre_trigger_window=timedelta(seconds=incidents.pre_trigger_seconds),
            persist_interval=timedelta(seconds=incidents.persist_interval_seconds),
            max_command_line=incidents.max_command_line,
            retention=timedelta(days=settings.history.incident_retention_days),
            maintenance_interval=timedelta(seconds=incidents.maintenance_interval_seconds),
        ),
    )
    return Monitor(
        system_reader=container.system_reader,
        process_reader=container.process_reader,
        clock=container.clock,
        evidence=evidence,
        intervals=SamplingIntervals(
            system_seconds=settings.sampling.system_interval_seconds,
            process_seconds=settings.sampling.process_interval_seconds,
            escalated_process_seconds=settings.sampling.pressure_process_interval_seconds,
        ),
        thresholds=thresholds,
        adaptive=AdaptivePolicy(
            escalation_max=timedelta(seconds=settings.sampling.pressure_escalation_max_seconds),
            cooldown=timedelta(seconds=settings.sampling.pressure_cooldown_seconds),
        ),
        own_pid=os.getpid(),
        health_log_interval_seconds=settings.agent.health_log_interval_seconds,
        incident_engine=engine,
    )
