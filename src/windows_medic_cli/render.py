"""Human-readable rendering of typed results. Formatting only; no decisions are made here."""

import json
from collections.abc import Sequence
from datetime import timedelta

import windows_medic
from windows_medic.application.operations import Executables, Locations, Runtime
from windows_medic.application.ports.startup_registry import Registration, StartupState
from windows_medic.application.use_cases.diagnose_slowdown import Diagnosis
from windows_medic.application.use_cases.doctor import CheckStatus, DoctorReport
from windows_medic.application.use_cases.get_system_health import (
    ProcessContribution,
    SystemHealth,
)
from windows_medic.application.use_cases.inspect_port import (
    PortInspection,
    PortOwner,
    UnresolvedOwner,
)
from windows_medic.application.use_cases.inspect_process import (
    ProcessInspection,
    RelatedProcess,
)
from windows_medic.application.use_cases.install_agent import InstallReport, UninstallReport
from windows_medic.application.use_cases.show_status import StatusReport
from windows_medic.domain.models.evidence import Evidence
from windows_medic.domain.models.finding import AffectedProcess, Finding
from windows_medic.domain.models.incident import IncidentSummary
from windows_medic.domain.models.metric import Metric, Unavailable, available
from windows_medic.domain.models.network import AddressFamily, ListeningEndpoint
from windows_medic.domain.models.repair import MemberResult, RepairCandidate, RepairRecord
from windows_medic.domain.models.tree import AncestryEnd, UnresolvedParent
from windows_medic.domain.policies.port_clearing import ClearPortEligibility
from windows_medic.domain.policies.protection import ProtectionLevel, ProtectionVerdict

_UNITS = ("B", "KiB", "MiB", "GiB", "TiB")
_KIB = 1024
_MINUTES_PER_HOUR = 60


def format_bytes(value: int | float) -> str:
    """Binary units with one decimal above bytes: ``1536`` -> ``1.5 KiB``."""
    amount = float(value)
    for unit in _UNITS[:-1]:
        if amount < _KIB:
            return f"{int(amount)} B" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= _KIB
    return f"{amount:.1f} {_UNITS[-1]}"


def format_metric[T](metric: Metric[T], render: str | None = None) -> str:
    """``render`` for available values, ``n/a (reason)`` otherwise."""
    if isinstance(metric, Unavailable):
        return f"n/a ({metric.reason.value})"
    return render if render is not None else str(metric)


def render_health(health: SystemHealth) -> str:
    """Render a :class:`SystemHealth` as a bounded plain-text report."""
    memory = health.memory
    window = f"{health.measurement_window_seconds:.1f} s"
    header = f"System health (measured over {window}, at {health.observed_at.isoformat()})"
    cpu = f"CPU: {_percent(health.cpu_percent)} of {health.cpu_count} logical processors"
    memory_line = (
        f"Memory: {format_bytes(memory.used_bytes)} used of {format_bytes(memory.total_bytes)}"
        f" ({memory.percent_used:.1f} %), {format_bytes(memory.available_bytes)} available"
    )
    commit = "Commit: " + format_metric(health.commit, _commit(health))
    processes = (
        f"Processes: {health.process_count} ({health.exited_process_count} exited,"
        f" {health.started_process_count} started during measurement)"
    )
    disk = (
        f"Disk I/O: read {_rate(health.disk_read_bytes_per_second)},"
        f" write {_rate(health.disk_write_bytes_per_second)}"
    )
    lines = [
        header,
        cpu,
        memory_line,
        commit,
        processes,
        disk,
        "",
        "Top CPU",
        *_table(health.top_cpu),
        "",
        "Top memory",
        *_table(health.top_memory),
    ]
    return "\n".join(lines) + "\n"


def _commit(health: SystemHealth) -> str | None:
    if not available(health.commit):
        return None
    used, limit = format_bytes(health.commit.used_bytes), format_bytes(health.commit.limit_bytes)
    return f"{used} of {limit} ({health.commit.percent_used:.1f} %)"


def _percent(metric: Metric[float]) -> str:
    return format_metric(metric, f"{metric:.1f} %" if available(metric) else None)


def _rate(metric: Metric[float]) -> str:
    return format_metric(metric, f"{format_bytes(metric)}/s" if available(metric) else None)


def _table(contributions: Sequence[ProcessContribution]) -> list[str]:
    if not contributions:
        return ["  (no contributors with an available measurement)"]
    rows = [("PID", "CPU%", "Working set", "Name")]
    for c in contributions:
        cpu = format_metric(
            c.cpu_percent, f"{c.cpu_percent:.1f}" if available(c.cpu_percent) else None
        )
        working_set = format_metric(
            c.working_set_bytes,
            format_bytes(c.working_set_bytes) if available(c.working_set_bytes) else None,
        )
        rows.append((str(c.identity.pid), cpu, working_set, format_metric(c.name)))
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    return [
        f"  {pid:>{widths[0]}}  {cpu:>{widths[1]}}  {memory:<{widths[2]}}  {name}"
        for pid, cpu, memory, name in rows
    ]


def render_inspection(inspection: ProcessInspection) -> str:
    """Render a :class:`ProcessInspection` as a bounded plain-text report."""
    o = inspection.observation
    identity = o.identity
    command_line = format_metric(
        o.command_line, " ".join(o.command_line) if available(o.command_line) else None
    )
    cpu_time = format_metric(
        o.cpu_time_seconds,
        f"{o.cpu_time_seconds:.1f} s" if available(o.cpu_time_seconds) else None,
    )
    created = identity.create_time.isoformat()
    heading = f"Process {format_metric(o.name)} (pid {identity.pid}, created {created})"
    user = f"User: {format_metric(o.username)} (session {format_metric(o.session_id)})"
    memory = f"Working set: {_bytes_metric(o.working_set_bytes)}, "
    memory += f"private: {_bytes_metric(o.private_bytes)}"
    threads = f"Threads: {format_metric(o.thread_count)}, handles: {format_metric(o.handle_count)}"
    risk = ", ".join(m.value for m in inspection.risk_markers) or "none"
    lines = [
        heading,
        f"Observed: {inspection.observed_at.isoformat()}",
        f"Executable: {format_metric(o.exe_path)}",
        f"Command line: {command_line}",
        user,
        f"CPU time: {cpu_time}",
        memory,
        threads,
        "",
        f"Parent: {_parent(inspection)}",
        "Ancestors (nearest first):",
        *_ancestors(inspection),
        _descendants_heading(inspection),
        *(_related_line(d, with_depth=True) for d in inspection.descendants),
        "",
        f"Protection: {_protection(inspection.protection)}",
        f"Risk markers: {risk}",
    ]
    return "\n".join(lines) + "\n"


def _bytes_metric(metric: Metric[int]) -> str:
    return format_metric(metric, format_bytes(metric) if available(metric) else None)


def _parent(inspection: ProcessInspection) -> str:
    link = inspection.parent
    if isinstance(link, UnresolvedParent):
        pid = "unknown" if link.parent_pid is None else f"pid {link.parent_pid}"
        return f"{pid} ({link.reason.value})"
    if inspection.ancestors:
        return _related_line(inspection.ancestors[0], with_depth=False).strip()
    return f"pid {link.pid}"


def _ancestors(inspection: ProcessInspection) -> list[str]:
    if not inspection.ancestors:
        if inspection.ancestors_truncated:
            return ["  ... (ancestors not shown)"]
        return [f"  (none: {_ancestry_end(inspection)})"]
    lines = [_related_line(a, with_depth=False) for a in inspection.ancestors]
    if inspection.ancestors_truncated:
        lines.append("  ... (more ancestors not shown)")
    elif inspection.ancestry_end is not AncestryEnd.UNRESOLVED:
        lines.append(f"  ... (walk stopped: {inspection.ancestry_end.value})")
    return lines


def _ancestry_end(inspection: ProcessInspection) -> str:
    if inspection.ancestry_end is AncestryEnd.UNRESOLVED:
        return "parent unresolved"
    return f"walk stopped: {inspection.ancestry_end.value}"


def _descendants_heading(inspection: ProcessInspection) -> str:
    if inspection.descendants_truncated:
        return f"Descendants: {len(inspection.descendants)} shown (more exist)"
    return f"Descendants: {len(inspection.descendants)}"


def _related_line(related: RelatedProcess, *, with_depth: bool) -> str:
    name = format_metric(related.name)
    depth = f", depth {related.depth}" if with_depth else ""
    protection = (
        "" if related.protection is ProtectionLevel.NONE else f" [{related.protection.value}]"
    )
    return f"  {name} (pid {related.identity.pid}{depth}){protection}"


def _protection(verdict: ProtectionVerdict) -> str:
    if not verdict.reasons:
        return verdict.level.value
    return f"{verdict.level.value} ({', '.join(r.value for r in verdict.reasons)})"


def render_port_inspection(inspection: PortInspection) -> str:
    """Render a :class:`PortInspection` as a bounded plain-text report."""
    lines = [
        f"TCP port {inspection.port} (observed {inspection.observed_at.isoformat()})",
        _owners_heading(inspection),
    ]
    if not inspection.owners and not inspection.unresolved:
        lines.append("  (nothing is listening on this port)")
    for owner in inspection.owners:
        lines.extend(_owner_lines(owner))
    if inspection.unresolved:
        lines.append(f"Unresolved listeners: {len(inspection.unresolved)}")
        lines.extend(_unresolved_line(u) for u in inspection.unresolved)
    lines.append(f"Clear-port plan: {_eligibility(inspection.clear_port)}")
    return "\n".join(lines) + "\n"


def _owners_heading(inspection: PortInspection) -> str:
    if inspection.truncated:
        return f"Owners: {len(inspection.owners)} shown (more exist)"
    return f"Owners: {len(inspection.owners)}"


def _owner_lines(owner: PortOwner) -> list[str]:
    o = owner.observation
    created = owner.identity.create_time.isoformat()
    command_line = format_metric(
        o.command_line, " ".join(o.command_line) if available(o.command_line) else None
    )
    listening = ", ".join(_endpoint(e) for e in owner.endpoints)
    risk = ", ".join(m.value for m in owner.risk_markers) or "none"
    return [
        f"  {format_metric(owner.name)} (pid {owner.identity.pid}, created {created})",
        f"    Listening on: {listening}",
        f"    Executable: {format_metric(owner.exe_path)}",
        f"    Command line: {command_line}",
        f"    User: {format_metric(owner.username)}",
        f"    Parent: {_owner_parent(owner)}",
        f"    Protection: {_protection(owner.protection)}",
        f"    Risk markers: {risk}",
    ]


def _owner_parent(owner: PortOwner) -> str:
    link = owner.parent
    if isinstance(link, UnresolvedParent):
        pid = "unknown" if link.parent_pid is None else f"pid {link.parent_pid}"
        return f"{pid} ({link.reason.value})"
    if owner.ancestors:
        return _related_line(owner.ancestors[0], with_depth=False).strip()
    return f"pid {link.pid}"


def _endpoint(endpoint: ListeningEndpoint) -> str:
    host = f"[{endpoint.address}]" if endpoint.family is AddressFamily.IPV6 else endpoint.address
    return f"{host}:{endpoint.port} ({endpoint.family.value})"


def _unresolved_line(unresolved: UnresolvedOwner) -> str:
    pid = "unknown" if unresolved.reported_pid is None else str(unresolved.reported_pid)
    return f"  {_endpoint(unresolved.endpoint)} reported pid {pid}: {unresolved.reason.value}"


def _eligibility(eligibility: ClearPortEligibility) -> str:
    if eligibility.eligible:
        return "eligible (all listeners resolved and unprotected)"
    return f"not eligible ({', '.join(b.value for b in eligibility.blockers)})"


def render_incidents(summaries: Sequence[IncidentSummary]) -> str:
    """Render incident summaries as a bounded table, newest first."""
    if not summaries:
        return "No incidents recorded.\n"
    rows = [("ID", "Kind", "Status", "Severity", "Started", "Duration", "Peak")]
    for summary in summaries:
        rows.append(
            (
                summary.id,
                summary.kind.value,
                summary.status.value,
                summary.severity.value,
                summary.started_at.isoformat(timespec="seconds"),
                _duration(summary),
                f"{summary.peak:.1f}",
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = [f"Recent incidents: {len(summaries)} (newest first)"]
    lines.extend(
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in rows
    )
    return "\n".join(lines) + "\n"


def _duration(summary: IncidentSummary) -> str:
    if summary.closed_at is None:
        return "ongoing"
    total = int((summary.closed_at - summary.started_at).total_seconds())
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{seconds:02d}s"
    return f"{minutes}m{seconds:02d}s" if minutes else f"{seconds}s"


def render_diagnosis(diagnosis: Diagnosis) -> str:
    """Render a :class:`Diagnosis` as a bounded plain-text report, findings ranked."""
    since, until = diagnosis.lookback
    current = diagnosis.current
    memory = current.memory
    pressure_cpu = " (pressure)" if diagnosis.pressure_now.cpu else ""
    pressure_memory = " (pressure)" if diagnosis.pressure_now.memory else ""
    evidence = diagnosis.evidence
    header = (
        f"Slowdown diagnosis: last {_minutes(until - since)}, measured at {until.isoformat()} "
        f"over {current.measurement_window_seconds:.1f} s"
    )
    now = (
        f"Now: CPU {_percent(current.cpu_percent)} of {current.cpu_count} logical processors"
        f"{pressure_cpu}, memory {memory.percent_used:.1f} % used "
        f"({format_bytes(memory.available_bytes)} available){pressure_memory}"
    )
    considered = (
        "Evidence considered: "
        f"{_count(evidence.incidents_in_window, 'incident')}, "
        f"{_count(evidence.incident_system_samples, 'system sample')}, "
        f"{_count(evidence.incident_contributor_samples, 'contributor sample')}; "
        f"{_count(evidence.processes_observed, 'process', 'processes')} observed; "
        f"{_count(evidence.hung_windows, 'hung window')} "
        f"({evidence.hung_windows_unverified} unverified)"
    )
    lines = [
        header,
        now,
        _incidents_heading(diagnosis),
        *_incident_rows(diagnosis.incidents),
        considered,
        "",
        _findings_heading(diagnosis),
    ]
    for number, finding in enumerate(diagnosis.findings, start=1):
        lines.extend(_finding_lines(number, finding))
    return "\n".join(lines) + "\n"


def _incidents_heading(diagnosis: Diagnosis) -> str:
    count = len(diagnosis.incidents)
    if count == 0:
        return "Incidents in window: 0"
    more = ", more not shown" if diagnosis.incidents_truncated else ""
    return f"Incidents in window: {count} (newest first{more})"


def _incident_rows(summaries: Sequence[IncidentSummary]) -> list[str]:
    if not summaries:
        return []
    rows = [("ID", "Kind", "Status", "Severity", "Started", "Duration", "Peak")]
    rows.extend(
        (
            s.id,
            s.kind.value,
            s.status.value,
            s.severity.value,
            s.started_at.isoformat(timespec="seconds"),
            _duration(s),
            f"{s.peak:.1f}",
        )
        for s in summaries
    )
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    return [
        "  " + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
        for row in rows
    ]


def _findings_heading(diagnosis: Diagnosis) -> str:
    count = len(diagnosis.findings)
    if count == 0:
        return "Findings: none"
    more = ", more not shown" if diagnosis.findings_truncated else ""
    return f"Findings: {count} (ranked{more})"


def _finding_lines(number: int, finding: Finding) -> list[str]:
    confidence = finding.confidence
    raised = ", ".join(r.value for r in confidence.raises) or "-"
    lowered = ", ".join(r.value for r in confidence.lowers) or "-"
    heading = (
        f"{number}. {finding.kind.value} [severity {finding.severity.value}, "
        f"confidence {confidence.level.value}]"
    )
    lines = [
        heading,
        f"   {finding.summary}",
        f"   confidence raised by: {raised}; lowered by: {lowered}",
        "   evidence:",
        *(f"     - {_evidence(e)}" for e in finding.evidence),
    ]
    if finding.affected_processes:
        lines.append("   processes: " + "; ".join(_affected(a) for a in finding.affected_processes))
    if finding.candidate_repairs:
        lines.append("   candidate repairs:")
        lines.extend(f"     - {_candidate(c)}" for c in finding.candidate_repairs)
    else:
        lines.append("   candidate repairs: none")
    return lines


def _evidence(evidence: Evidence) -> str:
    context: list[str] = []
    if evidence.incident_id is not None:
        context.append(f"incident {evidence.incident_id[:12]}")
    if evidence.window is not None:
        start, end = evidence.window
        context.append(f"{start.strftime('%H:%M:%S')}-{end.strftime('%H:%M:%S')}")
    suffix = f" ({', '.join(context)})" if context else ""
    return f"{evidence.detail}{suffix}"


def _affected(affected: AffectedProcess) -> str:
    exited = "" if affected.present else ", exited"
    markers = ", ".join(m.value for m in affected.risk_markers) or "-"
    return (
        f"{format_metric(affected.name)} ({affected.identity}{exited}) "
        f"protection {affected.protection.value}, markers {markers}"
    )


def _candidate(candidate: RepairCandidate) -> str:
    state = (
        "eligible"
        if candidate.eligible
        else "blocked by " + ", ".join(b.value for b in candidate.blockers)
    )
    elevation = ", needs elevation" if candidate.requires_elevation else ""
    return (
        f"{candidate.action.value} {candidate.target}: risk {candidate.risk.value}, "
        f"{state}{elevation}"
    )


def _count(number: int, singular: str, plural: str | None = None) -> str:
    noun = singular if number == 1 else (plural if plural is not None else singular + "s")
    return f"{number} {noun}"


def _minutes(value: timedelta) -> str:
    total = int(value.total_seconds() // 60)
    if total >= _MINUTES_PER_HOUR:
        hours, rest = divmod(total, _MINUTES_PER_HOUR)
        return f"{hours} h {rest:02d} min"
    return f"{total} min"


def render_repair(record: RepairRecord) -> str:
    """Render one :class:`RepairRecord`: what was asked, what happened, what was verified."""
    completed = "-" if record.completed_at is None else record.completed_at.isoformat()
    risk = "unassessed" if record.risk is None else record.risk.value
    elevation = ", elevation required" if record.requires_elevation else ""
    lines = [
        f"Repair {record.id}: {_repair_subject(record)} -> {_repair_status(record)}",
        f"Requested: {record.requested_at.isoformat()}, completed: {completed}",
        f"Risk: {risk}{elevation}",
    ]
    if record.members:
        gone = sum(1 for m in record.members if m.outcome.gone)
        lines.append(f"Members ({gone} of {len(record.members)} gone):")
        lines.extend(_member_rows(record.members))
    if record.appeared:
        lines.append(
            "Appeared after the plan (not targeted): "
            + ", ".join(str(identity) for identity in record.appeared)
        )
    if record.replacement is not None:
        lines.append(f"Replacement: {record.replacement}")
    if record.verification is None:
        lines.append("Verification: not performed")
    else:
        state = "passed" if record.verification.passed else "failed"
        lines.append(f"Verification: {state} ({record.verification.detail})")
    return "\n".join(lines) + "\n"


def render_repairs(records: Sequence[RepairRecord]) -> str:
    """Render repair records as a bounded table, newest first."""
    if not records:
        return "No repairs recorded.\n"
    rows = [("ID", "Action", "Status", "Target", "Requested", "Outcome")]
    rows.extend(
        (
            r.id[:_ID_WIDTH],
            r.action.value,
            r.status.value,
            _repair_target(r),
            r.requested_at.isoformat(timespec="seconds"),
            _repair_outcome(r),
        )
        for r in records
    )
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = [f"Recent repairs: {len(records)} (newest first)"]
    lines.extend(
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in rows
    )
    return "\n".join(lines) + "\n"


_ID_WIDTH = 12
_OUTCOME_WIDTH = 60


def _repair_subject(record: RepairRecord) -> str:
    if record.port is not None:
        owner = "" if record.target is None else f" ({record.target})"
        return f"{record.action.value} port {record.port}{owner}"
    return f"{record.action.value} {record.target}"


def _repair_status(record: RepairRecord) -> str:
    if record.rejection is not None:
        return f"{record.status.value} ({record.rejection.value})"
    return record.status.value


def _repair_target(record: RepairRecord) -> str:
    if record.port is not None:
        return f"port {record.port}"
    return "-" if record.target is None else f"pid {record.target.pid}"


def _repair_outcome(record: RepairRecord) -> str:
    if record.rejection is not None:
        return record.rejection.value
    if record.verification is None:
        return "-"
    detail = record.verification.detail
    return detail if len(detail) <= _OUTCOME_WIDTH else detail[: _OUTCOME_WIDTH - 3] + "..."


def _member_rows(members: Sequence[MemberResult]) -> list[str]:
    rows = [("Depth", "PID", "Name", "Outcome", "Detail")]
    rows.extend(
        (
            str(m.depth),
            str(m.identity.pid),
            format_metric(m.name),
            m.outcome.value,
            m.detail or "",
        )
        for m in members
    )
    widths = [max(len(row[i]) for row in rows) for i in range(4)]
    return [
        f"  {depth:>{widths[0]}}  {pid:>{widths[1]}}  {name:<{widths[2]}}  "
        f"{outcome:<{widths[3]}}  {detail}".rstrip()
        for depth, pid, name, outcome, detail in rows
    ]


# -- operational commands ---------------------------------------------------------------------

_LABEL_WIDTH = 17
_COMMANDS = (
    "Commands: health, diagnose, inspect <pid>, port <port>, incidents, "
    "terminate <pid> --create-time <ISO8601> [--tree], clear-port <port>, "
    "restart-component <explorer|dwm>, repairs, doctor, status, install-agent, "
    "uninstall-agent, config init|check, mcp-config "
    "(run `windows-medic <command> --help`)."
)


def _labelled(label: str, value: str) -> str:
    return f"{label + ':':<{_LABEL_WIDTH}}{value}"


def _version_line(runtime: Runtime) -> str:
    return (
        f"windows-medic {runtime.package_version} "
        f"(Python {runtime.python_version}, {runtime.python_executable})"
    )


def _configuration(locations: Locations) -> str:
    if locations.config_present:
        return f"{locations.config_file} (loaded)"
    return (
        f"{locations.config_file} (absent; built-in defaults, "
        "run `windows-medic config init` to create it)"
    )


def _location_lines(locations: Locations, executables: Executables) -> list[str]:
    return [
        _labelled("Data directory", str(locations.data_dir)),
        _labelled("Configuration", _configuration(locations)),
        _labelled("Database", str(locations.database)),
        _labelled("Agent log", str(locations.log_file)),
        _labelled("MCP server", f"{executables.mcp_server} (run `windows-medic mcp-config`)"),
    ]


def render_overview(runtime: Runtime, locations: Locations, executables: Executables) -> str:
    """Bare invocation: what this is, where its files are, what it can do."""
    lines = [_version_line(runtime), *_location_lines(locations, executables), _COMMANDS]
    return "\n".join(lines) + "\n"


def render_doctor(report: DoctorReport) -> str:
    lines = ["Windows Medic doctor"]
    lines.extend(
        f"  [{check.status.value}] {check.name}: {check.detail}" for check in report.checks
    )
    failed = sum(1 for check in report.checks if check.status is CheckStatus.FAILED)
    warnings = sum(1 for check in report.checks if check.status is CheckStatus.WARNING)
    if not failed and not warnings:
        lines.append("All checks passed.")
    else:
        parts = []
        if failed:
            parts.append(_count(failed, "check failed", "checks failed"))
        if warnings:
            parts.append(_count(warnings, "warning"))
        lines.append(", ".join(parts) + ".")
    return "\n".join(lines) + "\n"


def _startup(state: StartupState) -> str:
    if state.registration is Registration.REGISTERED:
        return f"registered ({state.command})"
    if state.registration is Registration.NOT_REGISTERED:
        return "not registered (run `windows-medic install-agent`)"
    return f"unknown ({state.detail})"


def render_status(report: StatusReport) -> str:
    agent = "not running"
    if report.agent.running:
        pids = ", ".join(f"pid {pid}" for pid in report.agent.pids) or "pid unknown"
        agent = f"running ({pids})"
    incident = "none"
    if report.latest_incident is not None:
        latest = report.latest_incident
        incident = (
            f"{latest.id} {latest.kind.value} {latest.status.value}, started "
            f"{latest.started_at.isoformat(timespec='seconds')}"
        )
    repair = "none"
    if report.latest_repair is not None:
        record = report.latest_repair
        repair = (
            f"{record.id} {_repair_subject(record)} {_repair_status(record)}, requested "
            f"{record.requested_at.isoformat(timespec='seconds')}"
        )
    lines = [
        _version_line(report.runtime),
        *_location_lines(report.locations, report.executables),
        _labelled("Agent", agent),
        _labelled("Startup", _startup(report.startup)),
        _labelled("Latest incident", incident),
        _labelled("Latest repair", repair),
    ]
    if report.store_problem is not None:
        lines.append(_labelled("Store problem", report.store_problem))
    return "\n".join(lines) + "\n"


def render_install(report: InstallReport, locations: Locations) -> str:
    written = "written" if report.config_created else "kept"
    lines = [
        f"Configuration {written}: {locations.config_file}",
        f"Logon task registered: {' '.join(report.command)}",
    ]
    if report.started:
        lines.append("Agent started.")
    elif report.start_requested:
        lines.append(
            "Agent start requested, but it was not seen running; it may have exited at once. "
            f"Check `windows-medic doctor` and {locations.log_file}."
        )
    elif report.already_running:
        lines.append("Agent already running; not started again.")
    else:
        lines.append("Agent not started (--no-start); it starts at your next logon.")
    lines.append(
        "Verify with `windows-medic doctor`; connect Claude Code with `windows-medic mcp-config`."
    )
    return "\n".join(lines) + "\n"


def render_uninstall(report: UninstallReport, locations: Locations) -> str:
    lines = ["Logon task removed." if report.unregistered else "No logon task was registered."]
    if report.stopped:
        lines.append("Agent stopped: " + ", ".join(f"pid {i.pid}" for i in report.stopped))
    if report.survivors:
        lines.append("Still running: " + ", ".join(f"pid {i.pid}" for i in report.survivors))
    if report.purged and report.data_dir_removed:
        lines.append(f"Data removed: {locations.data_dir}")
    elif report.purged:
        lines.append(
            f"Windows Medic data removed; {locations.data_dir} kept because it also holds "
            "files Windows Medic did not create."
        )
    else:
        lines.append(
            f"Data kept in {locations.data_dir} (incidents, repair audit, logs, config); "
            "add --purge-data to delete it."
        )
    return "\n".join(lines) + "\n"


def render_config_check(locations: Locations, effective: str) -> str:
    return f"Configuration: {_configuration(locations)}\n\n{effective}"


def render_mcp_config(executables: Executables) -> str:
    document = {
        "mcpServers": {"windows-medic": {"command": str(executables.mcp_server), "args": []}}
    }
    heading = (
        f"Claude Code MCP configuration (windows-medic {windows_medic.__version__}): "
        "save as .mcp.json in your project, or add the server with "
        f'`claude mcp add windows-medic -- "{executables.mcp_server}"`.'
    )
    return f"{heading}\n\n{json.dumps(document, indent=2)}\n"
