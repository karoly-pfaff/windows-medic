# Product specification — Windows Medic v1

## 1. Product statement

Windows Medic is a local-first Windows diagnostics and recovery agent with an MCP interface for Claude Code.

It exists to solve recurring workstation failures common during development: severe slowdown, memory pressure, sustained CPU usage, orphaned/stale process trees, occupied development ports, hung applications, and recoverable Windows-shell problems.

The product must preserve enough recent evidence to answer **what happened**, not merely show the current state after the problem has passed.

## 2. Primary user outcomes

A user can ask Claude:

- “Why is my machine slow?”
- “What made it slow ten minutes ago?”
- “What is eating RAM/CPU?”
- “Which process tree does this Node/Vite/Playwright process belong to?”
- “What owns port 5173?”
- “Is this process likely stale or orphaned?”
- “Kill that process tree safely.”
- “Free port 5173.”
- “Restart Explorer.”
- “Restart DWM.”

Claude receives structured evidence and invokes explicit recovery actions through MCP.

## 3. Non-goals

v1 is not:

- a generic remote-administration tool;
- an arbitrary shell executor;
- a task manager replacement GUI;
- a cloud monitoring product;
- an antivirus/EDR;
- a cross-platform process manager;
- an autonomous process killer;
- a performance tuning suite.

## 4. Runtime components

### 4.1 Windows Medic Agent

A lightweight unelevated process that starts at user logon and continuously gathers bounded system/process evidence.

Responsibilities:

- cheap system-pressure sampling;
- adaptive process sampling;
- process inventory and identity tracking;
- in-memory rolling history;
- incident lifecycle detection;
- persistence of incident evidence;
- self-health/overhead metrics.

### 4.2 Windows Medic MCP

A stdio MCP server started by Claude Code.

Responsibilities:

- expose bounded task-oriented diagnostic tools;
- invoke application use cases;
- expose explicit repair tools;
- map application results/errors to stable structured MCP output.

It does not own monitoring loops or diagnostic business logic.

### 4.3 Elevated repair helper

A one-shot helper used only by allowlisted repair recipes that genuinely require elevation.

It must not accept arbitrary executable/argument input from MCP. It accepts a stable recipe id plus validated typed arguments and returns a structured result.

## 5. Process identity

A process identity is `(pid, create_time)`.

Every stored process reference and every mutation target uses both values. Before a mutation, the target is re-resolved and its identity revalidated.

PID-only mutation is forbidden.

## 6. Monitoring behavior

### 6.1 Normal sampling

Initial defaults (configuration, not hard-coded policy):

- system sample interval: 2 seconds;
- normal process sample interval: 10 seconds;
- rolling in-memory evidence window: 30 minutes;
- persistent incident retention: 7 days;
- maximum incident count: bounded by retention and database maintenance.

Normal sampling must remain lightweight and tolerate inaccessible/exiting processes.

### 6.2 Adaptive sampling

When system pressure enters a suspect state, process sampling escalates temporarily (initial target: every 2 seconds) to identify contributors and trends.

Escalation has a bounded duration and cool-down; repeated pressure may extend an incident without creating an incident storm.

### 6.3 Minimum system metrics

- total CPU utilization;
- physical memory used/available/percentage;
- commit/pagefile data when reliable Windows adapter support is present;
- process count;
- disk aggregate I/O rate;
- Windows Medic agent CPU/memory overhead.

### 6.4 Minimum process metrics

When available:

- identity `(pid, create_time)`;
- executable name/path;
- command line;
- parent identity when resolvable;
- username/session id where available;
- CPU percent and accumulated CPU time;
- working set/private memory where available;
- I/O counters/rates;
- thread and handle count where available;
- TCP listening/connected ports when queried or relevant;
- GUI hung/responding evidence for visible apps when supported.

Unavailable fields are represented explicitly rather than fabricated.

## 7. Incident detection

v1 detects at least:

### 7.1 CPU pressure

Sustained high total CPU usage for a configurable duration.

Default candidate threshold: >= 90% for >= 20 seconds.

### 7.2 Memory pressure

Sustained critical memory pressure based on available physical memory and usage percentage.

Default candidate trigger: >= 90% memory used or <= 1.5 GiB available for >= 20 seconds.

### 7.3 Resource hog

A process/process tree contributes materially to sustained CPU or memory pressure. Attribution must be evidence-based and include the time window used.

### 7.4 Suspected orphan/stale development process

A process tree may be classified as suspected stale/orphaned when evidence supports it, for example:

- parent identity no longer exists or PID now refers to a different process;
- executable/command line matches a configurable development-process classifier;
- age exceeds policy threshold;
- the tree is not protected;
- additional evidence increases confidence.

No single heuristic such as process name is sufficient for destructive action.

### 7.5 Hung GUI process

When Windows reports one or more top-level windows as hung for a process, expose that as evidence. Do not infer “hung” solely from high CPU or low CPU.

### 7.6 Port conflict

Resolve listening TCP endpoints to exact process identities and process trees. UDP support is optional for v1 unless needed during implementation.

## 8. Incident lifecycle and evidence

An incident has:

- stable id;
- type(s);
- opened/closed timestamps;
- severity;
- observed thresholds;
- relevant system samples;
- relevant process samples and identities;
- findings with confidence and evidence references;
- repair candidates generated from policy;
- repair attempts and verification results.

The monitor keeps a bounded rolling window. When an incident opens, it preserves a pre-incident evidence window and captures an appropriate post-trigger window.

An incident is `open`, `recovering` or `closed` while the agent tracks it. When monitoring stops while an incident is live (the agent is stopped, crashes, or the machine reboots or logs off), the incident becomes `interrupted`: its end is the last time the agent observed it, and diagnosis treats it as past evidence, never as ongoing pressure. A graceful stop interrupts live incidents immediately; the next agent start interrupts any left behind by a run that ended abruptly.

Do not persist every process sample forever.

## 9. Diagnostic use cases

### `get_system_health`

Returns the current bounded system snapshot plus active pressure state and major contributors.

### `diagnose_slowdown`

Input: optional lookback window (bounded; default 30 minutes).

Returns:

- current state;
- incidents in window;
- ranked findings;
- evidence summary;
- confidence per finding;
- possible repair plans.

The application owns ranking and evidence construction; MCP does not improvise diagnoses.

### `inspect_process`

Returns identity, tree context, resource history summary, protection/risk flags, listening ports, and relevant incident links.

### `inspect_port`

Returns current owner identity/tree, command line summary, protection classification, and safe clear-port plan if eligible.

### `list_recent_incidents`

Returns a bounded incident summary list, newest first.

## 10. Repair use cases

### 10.1 Terminate process/tree

Supports explicit termination of an exact process identity or tree.

Before execution:

- revalidate identity;
- evaluate protection policy;
- calculate risk;
- refresh tree membership;
- reject critical/protected targets;
- record intended action.

After execution, verify target termination and report survivors/identity drift.

### 10.2 Clear port

Resolve the current listener immediately before mutation, ensure it still matches the planned process identity, terminate the eligible target/tree, and verify that the port is no longer owned/listening.

### 10.3 Restart Explorer

Explicit recipe:

- identify Explorer for the interactive user/session;
- terminate the exact identity;
- start Explorer if Windows does not recreate it as expected;
- verify a healthy Explorer process exists for the intended session.

### 10.4 Restart DWM

Explicit high-risk recipe. Never automatic.

The implementation must:

- identify the correct DWM process for the interactive session;
- require high-risk repairs to be enabled by configuration;
- use elevation if Windows requires it;
- terminate only the validated target identity;
- rely on/verify Windows recreation rather than launching arbitrary DWM instances;
- verify a new valid DWM identity appears for the session;
- return a clear partial-failure state if recreation cannot be verified.

### 10.5 Repair audit

Every repair attempt is persisted with target identity, action, risk, timestamps, result, and verification evidence.

## 11. Protection and risk policy

Critical Windows process protection includes at least system/session/security processes such as System, Registry, smss.exe, csrss.exe, wininit.exe, winlogon.exe, services.exe, and lsass.exe. The exact policy is centralized and tested.

Windows Medic processes protect themselves against accidental termination.

An action becomes higher risk when it targets:

- a Windows component;
- a process with ambiguous/stale identity;
- a process in an active Claude/terminal ancestry where user intent may be ambiguous;
- a process requiring elevation;
- a tree containing protected members.

High-risk actions are never automatic.

## 12. MCP surface for v1

Target tool set:

```text
get_system_health()
diagnose_slowdown(since_minutes=30)
inspect_process(pid, create_time=None)
inspect_port(port)
list_recent_incidents(limit=10)
terminate_process(pid, create_time, scope="process|tree")
clear_port(port)
restart_windows_component(component="explorer|dwm")
```

Mutation tools return structured before/action/after data.

No generic command, script, process-name kill, file write, registry write, or service control MCP tool exists in v1.

## 13. Configuration

Use typed configuration with safe defaults. Expected categories:

- sampling intervals and bounds;
- incident thresholds;
- history/retention;
- known development process classifiers;
- protected process policy additions;
- high-risk repair enablement;
- logging level;
- data directory.

Default data directory: under `%LOCALAPPDATA%\\WindowsMedic`.

Configuration errors fail fast at startup with actionable diagnostics.

Layout of the data directory: `config.toml` (generated on request with every key commented at its default), `incidents.sqlite3` (incidents and repair audit), `logs\\windows-medic-agent.log` (rotating, bounded), `elevated\\` (elevated helper results). `windows-medic status` prints every location; no repository knowledge is needed to find them.

## 13.1 Installation and startup

`windows-medic install-agent` registers a per-user Task Scheduler logon task that starts the agent unelevated, without a console window, at every logon; `uninstall-agent` removes it and keeps the user's evidence unless `--purge-data` is given. `windows-medic doctor` verifies the installation (runtime, configuration, writable data directory, database, executables, logon task, agent) and says what to do about each problem. Only one agent runs per data directory; a duplicate start exits with a distinct code and never starts a second monitoring loop.

## 14. Performance requirements

Target steady-state overhead on an ordinary development workstation:

- average agent CPU well below 1% when idle/normal;
- bounded memory with an initial target below 100 MiB;
- no unbounded queues, histories, logs, or query result sets;
- SQLite writes batched/throttled sufficiently to avoid becoming a disk-I/O source.

These are product targets to validate with soak tests, not assumptions.

## 15. Reliability requirements

The agent must survive/recover from:

- processes exiting mid-sample;
- access-denied process fields;
- PID reuse;
- temporary Windows API failures;
- SQLite busy/locked conditions within designed retry bounds;
- corrupt/incomplete individual observations;
- MCP client disconnects.

A collector failure should degrade one observation, not terminate the entire monitor.

## 16. Privacy and networking

v1 performs no network upload and no telemetry export.

MCP starts over stdio. LAN/Streamable HTTP is a later feature after security design; it is not required for v1 completion.

## 17. Later work (not in v1)

Each of these needs its own design and tests before it is built:

- Streamable HTTP transport on loopback;
- LAN exposure with authentication and a threat model;
- UDP port ownership;
- additional Windows recovery recipes (audio stack, network adapter, DNS, Bluetooth);
- an administrator-installed elevated helper in a protected location (`Program Files`),
  so UAC never elevates code the user's account can modify (`docs/safety-review.md` §5);
- configurable low-risk automatic remediation;
- richer historical trend queries;
- notifications or a tray UI;
- multi-machine support.
