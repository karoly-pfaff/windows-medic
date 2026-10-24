# Architecture — Windows Medic

## 1. Architectural style

Windows Medic uses pragmatic Clean Architecture / Hexagonal Architecture.

The purpose is not layer ceremony. The purpose is to keep Windows APIs, psutil, SQLite, MCP, process control, and elevation replaceable/testable while keeping diagnosis and safety policies deterministic.

```text
                         Claude Code
                             |
                           stdio
                             |
                    +------------------+
                    |  MCP interface   |
                    +---------+--------+
                              |
                              v
+----------------+    +---------------------+    +---------------------+
| CLI interface  | -> | Application usecases| <- | Background agent    |
+----------------+    +----------+----------+    +----------+----------+
                               |                          |
                               v                          v
                         +-----------+             application ports
                         |  Domain   |                    |
                         +-----------+                    v
                                                +---------------------+
                                                | Infrastructure      |
                                                | Windows / psutil    |
                                                | SQLite / clock      |
                                                | process control     |
                                                +---------------------+
```

The agent, the CLI and the MCP server are separate applications (separate import packages
of one distribution) that reuse the same core library through one composition root.

The agent is a process of its own, started at logon, because Claude Code starts the MCP
server only on demand while the evidence of a slowdown has to be captured when it
happens, usually before anyone asks. Incident history is therefore independent of the
Claude/MCP lifetime, the MCP server stays a thin, stateless interface over the same use
cases and persisted evidence, and the monitor can be measured and tuned on its own. The
price is one more process to install and start, and a store shared by concurrent
processes (§5.3, §14).

## 2. Source tree

One distribution, `windows-medic`, five import packages:

```text
pyproject.toml          the distribution, its scripts and the tooling configuration
src/
  windows_medic/        the core library: domain, application, infrastructure
  windows_medic_root/   the composition root: compose(), Container
  windows_medic_agent/  background monitor (windows-medic-agent[w])
  windows_medic_cli/    operational CLI (windows-medic)
  windows_medic_mcp/    MCP server for Claude Code (windows-medic-mcp)
tests/                  one shared test tree, mirrors the boundaries below
```

Dependencies between the packages point one way: `applications -> windows_medic_root ->
windows_medic`. The core never imports the composition root or an application, and the
applications reach infrastructure only through `compose()`; the import-linter contracts
in `pyproject.toml` enforce all of it on every gate.

The boundaries are packages, not distributions: everything is installed into one
environment, where only the contracts can stop an import, and nothing is installed
separately. One `pyproject.toml` declares one version and every script. Splitting a
package out later (for example to publish the core library) stays a mechanical change,
because the package boundaries and their contracts already exist.

```text
src/windows_medic/
  domain/
    models/
      metric.py             # Metric[T] = T | Unavailable(reason): no fake defaults
      process.py            # ProcessIdentity(pid, create_time), ProcessObservation
      samples.py            # SystemObservation, ProcessSnapshot, cumulative counters
      tree.py               # ProcessTree over exact identities; unresolved parents as evidence
      network.py            # ListeningEndpoint (owner reported as PID, never as identity)
      history.py            # RingBuffer bounded by time window and item count
      incident.py           # Incident aggregate, compact evidence samples, pure transitions
      evidence.py           # Evidence(kind, detail, value, window, identity, incident_id)
      finding.py            # Finding, Confidence + factors (closed vocabulary), AffectedProcess
      repair.py             # RepairCandidate (planning); RepairRecord audit: members, drift, verification
      gui.py                # HungWindow (owner reported as PID)
      component.py          # WindowsComponent (explorer, dwm), StartAttempt
      elevation.py          # ElevatedRecipe allowlist, ElevatedRequest/Result vocabulary
    policies/
      rates.py              # CPU %/bytes-per-second from two observations of one identity
      contributors.py       # bounded, total-ordered top-N ranking
      naming.py             # case-insensitive, separator-aware name/path/marker matching
      protection.py         # ordered protection levels with reasons (critical/self/user/component)
      risk_markers.py       # Claude/MCP/terminal ancestry, unresolved parent, protected descendant
      port_clearing.py      # clear-port eligibility with explicit blockers (planning only)
      pressure.py           # instantaneous pressure signal
      pressure_lifecycle.py # sustained pressure: none -> suspect -> open -> recovering -> closed
      adaptive_sampling.py  # normal -> escalated -> cooldown state machine
      evidence.py           # reduce observations into bounded incident evidence
      process_classification.py  # development classifier: names + command/path markers
      contributor_ranking.py     # merge incident + current contributions per identity
      pressure_findings.py       # CPU/memory pressure findings from incidents + now
      resource_hogs.py           # material contributors with the window they were seen in
      stale_dev_trees.py         # orphan dev trees: validated parent evidence required
      hung_gui.py                # Windows' not-responding verdict as evidence
      finding_assembly.py        # FindingLimits, affected-process builder, figure formats
      finding_ranking.py         # severity > confidence > kind > identity, bounded
      repair_risk.py             # protection/ancestry/tree context -> risk + blockers
      repair_planning.py         # process.terminate / terminate_tree candidates
      repair_execution.py        # termination order, rejection, verified outcomes, drift
      component_recovery.py      # session instance selection, replacement detection, recipes
    errors.py               # WindowsMedicError, ObservationError, ProcessNotFoundError, StaleIdentityError, IncidentStoreError, StartupRegistrationError, WorkspaceError

  application/
    ports/
      clock.py
      process_reader.py
      system_reader.py
      network_reader.py     # tcp_listeners(): the LISTEN table, owners as PIDs
      incident_repository.py # save/get/recent/active_since/purge_older_than
      hung_window_reader.py # hung_windows(): Windows' verdict, owners as PIDs
      process_controller.py # terminate(identity): exact identity, never a PID alone
      repair_audit.py       # save/get/recent/purge_older_than; raises RepairAuditError
      component_controller.py # start(component): Explorer from its fixed location only
      elevation.py          # run(ElevatedRequest) -> ElevatedResult; nothing else crosses
      startup_registry.py   # register/unregister/state/run_now: one command at user logon
      instance_guard.py     # try_acquire() -> InstanceLease | None: one agent per data dir
      workspace.py          # the data directory: ensure/probe/exists/size/write/remove
    operations.py           # Locations, Executables, Runtime; agent_command(), agent_processes()
    use_cases/
      get_system_health.py  # measure() + pure assess_health(); shared with diagnosis
      diagnose_slowdown.py  # bounded lookback -> Diagnosis (ranked findings, candidates)
      inspect_process.py
      inspect_port.py
      list_recent_incidents.py # bounded summaries, newest first
      terminate_process.py  # process.terminate / process.terminate_tree by exact identity
      clear_port.py         # port.clear: owner re-resolved before, port re-read after
      list_recent_repairs.py
      restart_windows_component.py # explorer/dwm: gate -> revalidate -> terminate -> verify replacement
      doctor.py             # RunDoctor: eight checks, each with status + what to do
      show_status.py        # ShowStatus: locations, agent/startup state, latest records
      install_agent.py      # InstallAgent (layout, config, task, start); UninstallAgent (task, --stop, --purge-data)
      init_config.py        # InitConfig: write the rendered defaults (refuses to clobber)
    services/
      repair_audit_trail.py # intent before mutation, outcome after, rejections; retention
      repair_executor.py    # revalidate -> policy -> audit intent -> act -> verify -> audit
    observability.py        # log_event(): structured event + fields convention

  infrastructure/
    windows/
      nt_process_enumeration.py  # one NtQuerySystemInformation call per inventory (§13)
      windows_process_reader.py  # ProcessReader: kernel inventory + psutil per-handle fields
      process_access.py          # limited-access probe; image path without a handle (denied processes)
      psutil_system_reader.py    # SystemReader: psutil + GetPerformanceInfo commit charge
      psutil_network_reader.py   # NetworkReader: one net_connections call, LISTEN only
      win32_performance.py       # narrow ctypes call for commit charge
      hung_window_reader.py      # EnumWindows + IsHungAppWindow, bounded, contained
      process_controller.py      # OpenProcess + GetProcessTimes check + TerminateProcess
      component_controller.py    # <SystemRoot>\explorer.exe, argument array, detached
      elevation_protocol.py      # argv/JSON wire format, strict parse, allowlisted recipes
      elevation_helper.py        # windows-medic-elevated: verify identity/name/session, act
      elevation_launcher.py      # ShellExecuteEx runas + bounded wait + result file
      task_scheduler.py          # StartupRegistry over schtasks.exe: XML logon task, least privilege
      single_instance.py         # InstanceGuard over a named mutex (Local\, per data directory)
    filesystem/
      local_workspace.py         # Workspace over pathlib/shutil; OSError -> WorkspaceError
    persistence/
      sqlite_connection.py       # WAL, busy_timeout, foreign keys, migrations applied on open
      sqlite_incident_repository.py  # short BEGIN IMMEDIATE transactions, bounded busy retries
      sqlite_repair_audit.py     # repairs + members + drift tables, same database
      sqlite_support.py          # shared supervisor (retries/transactions) and codecs
      migrations/                # ordered DDL scripts, schema_version table
    config/
      settings.py
      default_config.py     # render_default_config() (commented defaults), render_effective_config()
    observability/
      structured_logging.py # JSON-lines formatter; stderr handler + optional rotating file handler
    time/
      system_clock.py

src/windows_medic_root/
  container.py                        # Container, compose(), try_compose(), installed_executables()

src/windows_medic_agent/
  monitor.py              # asyncio supervisor: sequential samplers, contained failures, health
  evidence.py             # RollingEvidence: bounded system/process ring buffers
  wiring.py               # build_monitor(container): settings -> policies
  incident_engine.py      # per-kind lifecycle trackers -> incidents; throttled, contained writes;
                          # interrupts incidents left live by a previous run (at start) and its own (at stop)
  main.py                 # windows-medic-agent[w] [--duration SECONDS] [--log-file PATH]; exit 3 when already running

src/windows_medic_mcp/
  server.py               # MCPServer + 8 thin async tools bound to the container
  schemas.py              # Pydantic response models: bounded, explicit Unavailable values
  mapping.py              # typed results -> response models, no decisions

src/windows_medic_cli/
  main.py
  operations.py           # doctor/status/install-agent/uninstall-agent/config/mcp-config
  render.py               # typed result -> bounded plain text; no decisions
  __main__.py             # python -m windows_medic_cli
```

Test structure mirrors source boundaries rather than implementation filenames mechanically:

```text
tests/
  architecture/            # AST guards (domain purity, shell=True, execution surfaces), import-linter run
  unit/domain/
  unit/application/        # use cases and services over fake ports
  unit/infrastructure/
  unit/root/               # composition root
  unit/agent/
  unit/cli/
  unit/mcp/
  unit/soak/
  contract/                # packaging and entry-point contracts
  integration/windows/     # real OS, test-owned processes only
  integration/mcp/         # the real stdio server
  soak/                    # soak harness and load generators (python -m tests.soak)
  builders.py, fakes.py, containers.py   # shared test data, fake ports, fake containers
```

### 2.1 Dependency rules between packages

Enforced twice: by the import-linter contracts in `pyproject.toml` and by the AST guards
in `tests/architecture/`:

| Package                    | May import                                        | Never imports                                   |
| -------------------------- | ------------------------------------------------- | ----------------------------------------------- |
| `windows_medic.domain`         | itself, pure non-I/O stdlib                   | everything else, incl. `logging`                |
| `windows_medic.application`    | `domain`                                      | infrastructure, the composition root, the applications, mcp, psutil, pydantic, sqlite3 |
| `windows_medic.infrastructure` | `application`, `domain`                       | the composition root, the applications          |
| `windows_medic_root`      | all of `windows_medic`                        | the applications                                |
| `windows_medic_agent`, `_cli`, `_mcp` | `windows_medic_root`, `application`, `domain` | `infrastructure` (directly), each other |

Entry points (`windows_medic_cli.main`, `windows_medic_mcp.server`, `windows_medic_agent.main`)
obtain adapters only through `windows_medic_root.container.compose()`; that indirect
path to infrastructure is the intended one. The composition root is the one place that
knows the product's deliverables (`installed_executables()` names the console scripts).

## 3. Domain model

### 3.1 ProcessIdentity

```text
ProcessIdentity
  pid: int
  create_time: datetime
```

PID alone is not an identity. Windows reuses PIDs, so a diagnosis, and above all a
destructive action, that refers to a process by PID can reach the wrong one. Every
identity is `(pid, create_time)`; it is revalidated immediately before every mutation
and whenever a parent/child link is drawn from an observation that may be stale. Adapters
must therefore report reliable creation times, tests cover PID reuse, and an operation
whose target drifted fails safely with an identity-drift result instead of proceeding.

### 3.2 ProcessObservation

Represents observed facts at a point in time. Optional facts are explicit because Windows may deny or race individual reads.

### 3.3 ProcessTree

A snapshot graph using `ProcessIdentity` nodes. It may contain unresolved parent references; that is evidence, not automatically an orphan verdict.

Building the tree is pure, so it lives in the domain (`domain/models/tree.py`). A parent link is resolved only when a process with the reported parent PID exists in the same snapshot *and* was created no later than the child; otherwise the link is an `UnresolvedParent` with a reason (`parent_gone`, `parent_pid_reused`, `parent_unknown`, `invalid`). Ancestor walks are depth-bounded and cycle-guarded; descendant walks are breadth-first and bounded.

### 3.4 Incident

An incident is a lifecycle aggregate containing trigger facts, severity, findings, evidence references, and repair attempts.

### 3.5 Finding

A finding is an explainable diagnostic conclusion:

```text
Finding
  type
  severity
  confidence
  summary
  evidence[]
  affected_processes[]
  candidate_repairs[]
```

Confidence is not used as a decorative number; policies define what evidence raises/lowers it.

Implemented: `Finding.confidence` is a `ConfidenceAssessment(level, factors)` where every
factor names a `ConfidenceReason` from a closed vocabulary and whether it raised or lowered
the level; each finding policy computes the level from explicit rules over those factors.
Every `Evidence` item carries its kind, the measured value and window, and the identity or
incident it came from. A `RepairCandidate` must reference evidence and an exact target.

### 3.6 RepairPlan / RepairResult

Repair planning and repair execution are separate concepts. A plan captures the validated target, risk and preconditions. Execution revalidates mutable facts immediately before acting.

Implemented: a `RepairCandidate` is the plan a finding offers. `RepairRecord` is the audit of an
attempt: action, scope, exact target, risk, `RepairStatus` (`started`, `succeeded`, `partial`,
`failed`, `rejected`), the `RejectionReason` when policy refused before any OS call, one
`MemberResult` per tree member (`terminated`, `already_gone`, `access_denied`,
`still_running`, `error`), the identities that appeared under planned members after the plan
(identity drift) and the observed `Verification`. Success is never a return code: a member
counts as terminated only when it is verifiably gone afterwards.

## 4. Application ports

Ports should model capabilities needed by use cases, not mirror libraries.

Examples:

```python
class ProcessReader(Protocol):
    def snapshot(self) -> Sequence[ProcessObservation]: ...
    def get(self, identity: ProcessIdentity) -> ProcessObservation | None: ...

class ProcessController(Protocol):
    def terminate(self, identity: ProcessIdentity) -> TerminationOutcome: ...
    def terminate_tree(self, tree: ProcessTree) -> TreeTerminationOutcome: ...

class NetworkReader(Protocol):
    def tcp_listeners(self) -> tuple[ListeningEndpoint, ...]: ...
```

Avoid a generic `WindowsCommandRunner` application port. That leaks mechanism into policy and invites arbitrary command execution.

The listener table reports owners as PIDs only. `InspectPort` therefore takes a process baseline *before* reading the table, maps each reported PID to the identity it had at baseline, and re-resolves that exact identity *after*; an owner that cannot be confirmed is reported as `owner_changed`/`owner_unverified`/`owner_unknown` rather than as whichever process now holds the PID. Clear-port eligibility is a domain policy (`port_clearing.py`) that returns explicit blockers; `ClearPort` executes an eligible plan through the repair executor (§8).

## 5. Monitoring architecture

### 5.1 Two-level sampler

Normal mode:

- system metrics every ~2 s;
- process metrics every ~10 s;
- maintain a bounded ring buffer;
- maintain lightweight process identity/inventory state.

Pressure/suspect mode:

- temporarily increase process sampling to ~2 s;
- calculate deltas/trends;
- open or extend incidents when duration thresholds are met;
- capture pre-trigger evidence from the ring buffer.

This avoids sampling every field from every process at maximum frequency indefinitely.

Implemented in `windows_medic_agent/monitor.py`: three sequential asyncio loops (system sampler, process sampler, health log) under one `TaskGroup`. Each loop runs one iteration, then waits for the remainder of its interval; a slow iteration delays the next and is counted as an overrun, so a sampler can never overlap itself. Blocking OS reads run via `asyncio.to_thread`. The process sampler's interval follows the adaptive state (`domain/policies/adaptive_sampling.py`), which is driven by the instantaneous pressure signal of each system sample; a mode change wakes the process sampler so the new cadence applies immediately; escalation is bounded and followed by a cool-down. Evidence lives in `windows_medic_agent/evidence.py` ring buffers bounded by both the rolling window and item caps (`[history] max_system_samples`, `max_process_snapshots`). The agent's own CPU share and working set are derived from its own entry in each process snapshot, and sampling durations are measured; both are logged as `agent.health`.

### 5.2 Agent supervisor

Collectors run under supervision. Failure to read one process or one collector must not terminate the agent.

Each collector returns partial observations plus typed availability/error metadata where useful. Infrastructure failures are logged; expected process-race failures are normalized.

### 5.3 Persistence

SQLite uses WAL mode and short transactions.

Persist:

- incident metadata;
- selected incident system/process evidence;
- findings;
- repair attempts/results;
- optional downsampled system history if required by diagnosis.

Do not persist an unbounded raw firehose.

Retention cleanup is a normal maintenance operation.

Implemented: `infrastructure/persistence/` opens `<data_dir>/incidents.sqlite3` in WAL mode with a bounded `busy_timeout`, applies ordered migrations, and stores each incident with its compact evidence (bounded system samples, top contributors) in one short `BEGIN IMMEDIATE` transaction. Transient `locked`/`busy` errors are retried a bounded number of times, then surface as `IncidentStoreError`; the agent's incident engine logs, counts and retries on a later tick instead of failing the sampling loop. Writes are paced by `[incidents] persist_interval_seconds` while an incident is open and immediate on lifecycle transitions. Retention (`[history] incident_retention_days`) runs from the agent's health loop once per `[incidents] maintenance_interval_seconds`.

## 6. Diagnosis architecture

`diagnose_slowdown` is an application orchestration use case.

It combines:

1. current system state;
2. recent incident evidence;
3. process/tree classification;
4. pressure policies;
5. evidence ranking;
6. safe repair candidates.

It returns a typed `Diagnosis`, not prose.

Implemented: `DiagnoseSlowdown` loads the incidents active inside a bounded lookback
(`IncidentRepository.active_since`), takes the same two-sample measurement as
`get_system_health`, reads Windows' hung-window verdicts and pins each reported PID to the
identity it had in the measurement snapshot (re-resolved; otherwise *unverified*). Pure
domain policies then do the reasoning: `contributor_ranking` merges incident contributors
and current contributions per exact identity and ranks by the largest share of the machine
seen anywhere in the window; `pressure_findings`, `resource_hogs`, `hung_gui` and
`stale_dev_trees` build findings; `repair_planning` attaches `process.terminate` /
`process.terminate_tree` candidates (assessed by `repair_risk`) only when confidence is at
least medium; `finding_ranking` orders and bounds the result. Ranking, evidence ranking and
repair planning therefore live in `domain/policies` rather than an `application/services`
package: they are pure and need no ports.

MCP mapping turns it into a concise model-friendly response; Claude can then explain it conversationally.

## 7. Process-tree correctness

Building trees is race-prone. Rules:

- resolve identities using PID + create time;
- retain unresolved parent references as evidence;
- before mutation, rebuild/revalidate the target tree;
- do not assume a reused parent PID is the original parent;
- terminate children before parent where appropriate;
- after termination, verify by identity, not only PID absence;
- report survivors and access-denied members.

## 8. Repair architecture

Repairs use a recipe registry internal to the infrastructure/application boundary. It is a fixed allowlist, not a plugin shell.

Each recipe exposes metadata and typed arguments. Example ids:

```text
process.terminate
process.terminate_tree
port.clear
windows.explorer.restart
windows.dwm.restart
```

The application policy chooses whether a recipe is eligible and assigns risk. Infrastructure performs the mechanism.

### 8.1 Elevation

Normal processes remain unelevated.

When a recipe requires admin rights, use a one-shot elevated helper. The helper accepts only known recipe ids and schema-validated parameters. It must reject arbitrary executable paths/commands.

The initial implementation may use Windows UAC launch semantics. A long-running privileged service is explicitly out of scope unless later evidence justifies it.

Implemented: `windows-medic-elevated` is a console script launched by `UacElevationLauncher`
through `ShellExecuteExW("runas")` with an argument array encoded by `elevation_protocol`:
`<recipe> --pid N --create-time ISO --session N --result <file.json>`. The only recipe is
`windows.dwm.terminate`. The helper parses strictly (unknown recipe / malformed argument ->
rejection), then re-derives every fact from the live process table — the identity must
exist unchanged, its image name must be `dwm.exe` and it must live in the requested session —
before calling the same exact-identity `terminate_exact` the unelevated process uses. It writes
a typed JSON result (completed / rejected / failed) that the launcher reads back after a
bounded wait; a cancelled UAC prompt is *declined*, a slow helper *timed out*. No executable,
command line or process name can be passed across the boundary.

Component recipes (`RestartWindowsComponent`): the instance to restart is the oldest
`explorer.exe` / `dwm.exe` in the caller's session; DWM is high risk and rejected unless
`[repairs] high_risk_repairs_enabled = true`. The identity is revalidated immediately before
termination; Explorer is terminated unelevated and, if Windows has not recreated it within
`explorer_auto_restart_wait_seconds`, started from `<SystemRoot>\explorer.exe` (no arguments);
DWM is terminated only through the helper and never started by Windows Medic. Verification
requires the old identity to be gone and a *new* instance for the session to be observed in
two consecutive snapshots; otherwise the record is a clear partial failure.

### 8.2 Repair verification

Every recipe defines a postcondition.

Examples:

- terminate: old `ProcessIdentity` no longer exists;
- clear port: no listener remains for the target port (or owner changed, reported distinctly);
- Explorer restart: valid Explorer exists in target user session;
- DWM restart: old identity is gone and a new DWM identity for the session appears within bounded timeout.

Implemented (`application/services/repair_executor.py`): fresh snapshot -> every target revalidated
by exact identity (`target_not_found` / `stale_identity`) -> protection and risk on that snapshot
(`target_protected`, `tree_contains_protected`, `tree_too_large` reject before any OS call) ->
members from the fresh tree, target first, then descendants by depth -> the intended action is
written to the audit (no audit, no mutation) -> `ProcessController.terminate` per member, which
itself re-checks the create time behind the PID -> bounded polling of the process table until
every member is gone or the timeout passes -> survivors, drift and the caller's extra
postcondition (the port table for `port.clear`) are reported, never hidden -> the outcome is
audited. Process termination is never elevated: a member the unelevated process may not
touch is reported as `access_denied` with `requires_elevation` on the record.

## 9. Protection policy

Centralized domain policy classifies targets into protected/risk groups.

Inputs may include:

- executable identity/name/path;
- session;
- process ancestry/tree membership;
- Windows component classification;
- Windows Medic self identities;
- active Claude/MCP ancestry;
- configured user additions.

A tree containing a critical protected member cannot be blindly killed as a tree.

Implemented as `domain/policies/protection.py`: an ordered `ProtectionLevel` (`none < windows_component < protected < critical`) with explicit `ProtectionReason`s. Critical names (System, Registry, smss, csrss, wininit, winlogon, services, lsass, ...) are protected even when the executable path cannot be read; Windows Medic's own process (by PID) and other Windows Medic processes (by path/command-line marker) are `protected`; user additions are `protected`; known shell/service components and anything under `%SystemRoot%` are `windows_component`. `domain/policies/risk_markers.py` adds tree evidence: Claude Code / Windows Medic / terminal ancestry, unresolved parent, protected descendant.

## 10. MCP boundary

Use official MCP Python SDK v2 `MCPServer`.

Initial transport: stdio.

Tool handlers are thin and have bounded output. MCP schemas use Pydantic/boundary models as appropriate; domain remains framework-free.

MCP v1 tool set is specified in `product-spec.md`.

Do not use MCP protocol features as internal application state management. The background agent/persistence owns history independently of MCP client lifetime.

Implemented: `windows_medic_mcp/server.py` builds the `MCPServer` from the composed container
(`create_server(container)`); each tool is an `async` closure that validates only what the
JSON schema cannot (the ISO 8601 `create_time`), runs exactly one use case on a worker
thread (`anyio.to_thread.run_sync`, so the transport stays responsive during measurement
windows and repair verification) and maps the typed result through `mapping.py` into the
`schemas.py` response models, which the SDK publishes as `outputSchema` and returns as
structured content. Argument bounds (port, pid, lookback, limit, literal component/scope)
live in the input schema, with the configurable maxima taken from settings at build time.
`WindowsMedicError` and boundary `ValueError`s become `ToolError` (`isError` results with the
message); anything else is a crash the SDK reports generically and logs with its traceback
on stderr. Mutation tools carry `destructiveHint` and a `MUTATION:` description and return
`RepairResponse` (`mutation: true`, before/after). An import-linter contract forbids
`windows_medic_mcp` from importing `domain.policies` or `application.services`, so the
handlers cannot grow business logic. The SQLite `Database` is shared across threads under
one lock (`check_same_thread=False` + `RLock` in `SqliteSupervisor`).

## 11. Configuration

Configuration is loaded at composition root, validated once, and passed as typed settings/policies.

No domain code reads environment variables or files directly.

Settings layers:

1. safe built-in defaults;
2. user config file under `%LOCALAPPDATA%\\WindowsMedic`;
3. narrowly supported environment overrides for development/testing.

`config.toml` is generated from the settings models (`infrastructure/config/default_config.py`),
never hand-maintained: every section and key appears commented at its default, so the file
cannot drift from what `load_settings` accepts. `windows-medic config check` renders the
values in force the same way.

### 11.1 Installation and startup

The composition root turns settings into `Locations` (data directory, config file and
whether it was present, database, log directory/file, elevated results) and `Executables`
(the console/GUI scripts next to the interpreter); operational use cases receive these as
plain values and reason about them through three ports:

- `StartupRegistry` (`infrastructure/windows/task_scheduler.py`): one Task Scheduler logon
  task, `WindowsMedic\\Agent`, created from an XML definition through `schtasks.exe` with an
  argument array — `LogonTrigger` for the current user, `InteractiveToken`,
  `LeastPrivilege`, hidden, no execution time limit, `MultipleInstancesPolicy=IgnoreNew`.
  The command is `windows-medic-agentw.exe --log-file <data_dir>\\logs\\windows-medic-agent.log`:
  the GUI-subsystem launcher runs `pythonw`, so no console window appears and the standard
  streams do not exist; the agent falls back to a null stream and the log file carries the
  events. Task state is read back from the task XML with two anchored patterns (no XML
  parser: the document is local and only two leaf elements matter).
- `InstanceGuard` (`infrastructure/windows/single_instance.py`): a named mutex
  `Local\\WindowsMedic.Agent.<sha256(data_dir)[:16]>` owned for the agent's lifetime and
  released by the kernel on exit, so a crash never leaves a stale lock. One agent per data
  directory: a second start exits with code 3 after logging `agent.already_running`; the
  CLI probes the same mutex (acquire and release immediately) to report whether an agent
  runs. A test agent against a temporary data directory never collides with the installed one.
- `Workspace` (`infrastructure/filesystem/local_workspace.py`): the handful of file
  operations the commands need; `OSError` becomes `WorkspaceError`.

`InstallAgent` is idempotent (creates what is missing, keeps an existing configuration,
replaces the task, starts the agent unless one already holds the mutex). `UninstallAgent`
removes the task; `--stop` terminates agent processes — the launcher *and* the interpreter
it spawned, both matched through `agent_processes()` by launcher name or a command line
mentioning it, never the calling process — by exact identity through `ProcessController`
and waits, bounded, for them to disappear; `--purge-data` deletes the data directory only
when no agent runs, after releasing the caller's own database handle (Windows cannot
delete an open file). `RunDoctor` changes nothing and reports eight checks (runtime,
configuration, data directory writable, database answers, executables present, logon task,
agent, elevation exposure) each with a status and the command that fixes it.

## 12. Observability

Use structured logs with event names and relevant stable ids (incident id, process identity, repair id). Avoid dumping full command lines into normal logs when not needed; command lines can contain secrets.

Mechanism: `application.observability.log_event(logger, "incident.opened", incident_id=...)` attaches typed fields to a stdlib log record; `infrastructure.observability.structured_logging` renders one bounded JSON object per line (`ts`, `level`, `logger`, `event`, fields) on stderr. Records exceeding the line bound are replaced by their envelope plus `"truncated": true`. stdout is never used for logs because the MCP stdio transport owns it.

The agent can additionally write the same lines to a rotating file (`--log-file`; the logon
task always passes `<data_dir>\\logs\\windows-medic-agent.log`), bounded by
`[logging] file_max_bytes` × `file_backup_count`, so an agent that runs for weeks cannot
fill the disk. The composition root owns the handler and closes it with the container.

The agent records its own sampling duration and resource overhead so a soak test can prove it remains lightweight.

## 13. Dependency choices

Prefer a small dependency set:

- `mcp[cli]` v2: MCP server/development tooling;
- `psutil`: system/process primitives;
- `pydantic`/`pydantic-settings`: boundary/config validation if useful;
- test/dev dependencies: pytest, pytest-cov, hypothesis, ruff, mypy, import-linter.

Use stdlib `sqlite3` unless an ORM demonstrates concrete value. An ORM is not expected to add value for the bounded incident schema.

Use `ctypes` or a narrow Windows adapter for small Win32 calls instead of adopting a broad dependency solely for one function.

psutil is the per-process/per-handle primitive, not the inventory mechanism: on Windows its per-process `ppid()`/`num_threads()` calls each enumerate the whole system, which makes a full inventory O(N²). The inventory is therefore one `NtQuerySystemInformation(SystemProcessInformation)` call
per snapshot (ctypes, no extra dependency), which yields for every process at one
instant: pid, parent pid, create time, CPU time, thread and handle counts, working set,
private bytes, I/O counts, session id and image name. A full inventory costs one system
call instead of seconds of CPU, and every identity's `create_time` comes from one source,
the kernel's 100 ns `CreateTime`. The System Idle Process (pid 0) is not emitted: its
"CPU time" is idle time, not a workload. The structure layout must match the Windows ABI;
unit tests cover it over synthetic buffers and integration tests against the live
process table. psutil supplies executable path, command line and username per process that grants limited query access. A process that denies it is not opened through psutil at all (psutil learns a denial only after a further full enumeration, per field): `process_access.py` reads its image path without a handle (`SystemProcessIdInformation`) and the other fields are `access_denied`.

## 14. Concurrency model

Prefer one asyncio agent supervisor with bounded periodic tasks and offload blocking OS calls deliberately where needed.

Do not introduce multiprocessing until profiling proves it necessary.

SQLite access is serialized through a small persistence adapter/connection policy; do not share cursors across tasks.

## 15. Security posture

Local-first does not mean trusted-input-free.

- no `shell=True`;
- no generic command execution: a command runner would be convenient, but it would
  collapse the safety boundary and make MCP equivalent to a remote shell. The product
  exposes only typed, allowlisted diagnostic and repair capabilities; adapters may call
  OS tools internally with argument arrays where no direct API is practical, but no
  caller can ever supply a command string or an executable path, so every new repair
  needs an explicit recipe and its tests;
- validate port ranges, PIDs, timestamps, recipe ids, component ids;
- revalidate mutable process identities before repair;
- log repairs;
- bind future HTTP to loopback by default;
- LAN transport requires dedicated authentication/threat-model work before enablement.

## 16. Architectural fitness functions

CI/local quality gate should enforce:

- Ruff format/lint;
- mypy strict;
- import-linter contracts;
- pytest unit/contract suite;
- branch coverage gate;
- Windows integration suite where available;
- no forbidden `shell=True` pattern (lint/test guard);
- a closed, per-module allowlist of process start/stop call sites and no subprocess call
  with a command string (`tests/architecture/test_execution_surfaces.py`);
- MCP contract/schema tests;
- package/entry-point smoke tests.

Outside the automatic gate, the soak harness (`tests/soak`) measures the agent from the
outside against the product-spec §14 targets and the stress suite
(`tests/integration/windows/test_stress.py`) drives real pressure transitions, churn and
persistence faults; both are described in `docs/testing-strategy.md`.
