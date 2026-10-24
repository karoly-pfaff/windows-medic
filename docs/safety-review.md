# Safety review — repair and execution surfaces (v1)

Reviewed against the code as it stands, including the findings of a full pre-release code
review. The review
asks one question per surface: can any caller — Claude through MCP, a user at the CLI, a
process on the machine, or a corrupted store — make Windows Medic start something it did
not choose itself, or stop something it did not verify itself?

The conclusion (§5) is enforced continuously by `tests/architecture/test_execution_surfaces.py`,
which fails when a process start/stop call appears anywhere outside the four reviewed
adapters or when a subprocess call is handed a command string.

## 1. Threat model

In scope:

- **Prompt-injected or mistaken model input** through MCP: arbitrary strings, out-of-range
  numbers, stale identities, repeated calls.
- **A local, unprivileged process** that reuses a PID, starts a listener on a port that was
  just inspected, or names itself like a Windows component.
- **A hostile or corrupt data directory**: config values, database contents, result files
  of the elevated helper.
- **Operator mistakes**: running `uninstall-agent --purge-data` while the agent runs,
  registering the logon task twice, starting two agents.

Out of scope for v1 (documented, not mitigated): an attacker who already runs code as the
same user can do everything the user can, including editing `config.toml`; LAN exposure
does not exist (stdio only, product-spec §16).

## 2. Inputs that cross a boundary

| Boundary | Inputs | Validation |
| -------- | ------ | ---------- |
| MCP tools (`windows_medic_mcp/server.py`, `schemas.py`) | `pid`, `create_time`, `port`, `since_minutes`, `limit`, `scope`, `component` | Pydantic field constraints (`0 <= pid <= 2**32 - 1`, `1 <= port <= 65535`, bounded `limit`/`since_minutes`, closed enums); invalid input is an `isError` result, never executed. There is no string argument that names a process, an executable or a command. |
| CLI (`windows_medic_cli/main.py`, `operations.py`) | the same, plus `--force`, `--stop`, `--purge-data`, `--no-start` | argparse types (`_pid`, `_port`, `_aware_datetime`, `_positive_int`), closed choices for components; usage errors exit 2. |
| Configuration (`infrastructure/config/settings.py`) | `config.toml`, three environment overrides | Pydantic models with ranges on every numeric field; unknown keys and `config_file` in the file are rejected; failure exits 2 before anything starts. User-added protected names only *add* protection. |
| Elevated helper argv (`infrastructure/windows/elevation_protocol.py`) | recipe id, pid, create time, session, result path | Strict parse into `ElevatedRequest`; the recipe is a closed `StrEnum` with one member (`windows.dwm.terminate`). No executable, command line or name can be passed. The result path is written as administrator only if it is named `elevated-<32 hex>.json`, its directory is reached without junctions or symbolic links, and the file does not exist yet (exclusive create): the elevated write cannot be redirected or replace a file. |
| Elevated result file | JSON written by the helper | Strict parse; a missing or malformed file, including unknown enum values, is `FAILED`, never `COMPLETED` and never an exception. |
| Task Scheduler XML | the task definition Windows Medic wrote, read back | Two anchored regexes for `<Command>`/`<Arguments>`; no XML parser, no entity expansion; only used for display. |
| SQLite rows | incidents, repair audit | Typed decoding; a broken store surfaces as `IncidentStoreError`/`RepairAuditError` and degrades one command (doctor/status report it). Nothing in the store is ever executed or used to pick a target. |

## 3. Mutation surfaces

Every mutation goes through one application use case in the core library; the MCP and CLI
applications only validate and render (import-linter contract "MCP handlers are thin";
the applications cannot import infrastructure at all).

| Surface | Entry points | What it can touch | Identity discipline | Policy gates | Verification and audit |
| ------- | ------------ | ----------------- | ------------------- | ------------ | ---------------------- |
| Terminate process / tree | `terminate_process` (MCP), `windows-medic terminate` | One exact `(pid, create_time)` and, for trees, its descendants resolved from a fresh snapshot immediately before acting; terminated parents first so a supervisor cannot respawn its children | `RepairExecutor` re-resolves the target; a reused PID is `stale_identity`; the controller re-checks `GetProcessTimes` on the open handle before `TerminateProcess` | `ProtectionPolicy` (critical Windows processes, Windows Medic itself — recognised by its executable and script *file names*, never by a folder name — user-configured names, Windows components) rejects before any OS call; tree size bound (`max_tree_members`); protected member anywhere in a tree rejects the whole tree | Intent recorded before acting, outcome after — also when verification cannot observe (`unverified`, `failed`); verified by observation until the members are gone; processes that appeared during the plan are reported as drift. Repairs in one process run one at a time (the audit trail's lock), so parallel MCP calls never interleave |
| Clear port | `clear_port` (MCP), `windows-medic clear-port` | The confirmed owner(s) of one TCP port | Baseline snapshot → listener table (PIDs only) → re-resolution to exact identities; an owner that changed is rejected, not replaced | As above, plus explicit eligibility blockers (`port_clearing.py`) | Port re-read afterwards; success only when nothing listens |
| Restart Explorer | `restart_windows_component` (MCP), `windows-medic restart-component explorer` | The session's `explorer.exe` instance; starts `%SystemRoot%\explorer.exe` if Windows does not | Instance selected by session; terminated by exact identity | Component recipe is a closed enum; risk medium; audited | Verified by observing a *new* instance |
| Restart DWM | same, `dwm` | The session's `dwm.exe`, through the elevated helper | Helper re-derives everything: identity exists, is `dwm.exe`, is in the requested session | Disabled by default (`[repairs] high_risk_repairs_enabled`); never automatic; UAC prompt is the elevation | Helper writes a typed result; caller verifies the replacement itself |
| Stop agents | `windows-medic uninstall-agent --stop` | The agent launchers (by image name) and Python interpreters whose script argument is a launcher; a program that merely mentions a launcher (an editor) is not matched; never the calling process | Terminated by exact identity through the same controller; bounded wait; survivors reported (exit 1) | Not exposed through MCP | Verified by re-reading the process table |
| Purge data | `windows-medic uninstall-agent --purge-data` | Only the files Windows Medic writes (database and its WAL/SHM, `config.toml` in the data directory, the agent log and its rotations, elevated result files), then each directory only if empty: a data directory pointed at a folder of the user's own files keeps them | — | Refused while an agent holds the instance mutex or survivors remain; the caller's own database handle is released first | Not exposed through MCP |
| Logon task | `install-agent` / `uninstall-agent` | One Task Scheduler task, `WindowsMedic\Agent` | The command is computed by Windows Medic (`agent_command`), never taken from input | Least privilege, current user, no elevation | State read back after registration; "not registered" only when the full task list confirms it (schtasks messages are localized); "started" only once the agent is seen holding its instance lock |

Automatic remediation does not exist in v1: the agent observes and persists; only an
explicit MCP/CLI call mutates (product-spec §10, CONTRIBUTING.md "No speculative repair").

## 4. Execution surfaces (process start/stop call sites)

| Module | Call | Executable / handle | Arguments | Why it is safe |
| ------ | ---- | ------------------- | --------- | -------------- |
| `infrastructure/windows/process_controller.py` | `kernel32.TerminateProcess` | A handle opened on one PID whose create time was just compared with the requested identity | exit code constant | Cannot terminate anything but the exact identity a use case verified and policy allowed |
| `infrastructure/windows/component_controller.py` | `subprocess.Popen` | `<SystemRoot>\explorer.exe` (fixed) | none | Path derived from configuration validated at startup; argument array; no shell; detached |
| `infrastructure/windows/task_scheduler.py` | `subprocess.run` | `<SystemRoot>\System32\schtasks.exe` (fixed) | `/Create /F /TN <fixed> /XML <temp file>`, `/Delete`, `/Query` (one task, or the full list as CSV), `/Run` | Argument array; task name fixed; the XML is generated from `agent_command()`, user strings are XML-escaped; `CREATE_NO_WINDOW`; timeout |
| `infrastructure/windows/elevation_launcher.py` | `shell32.ShellExecuteExW` (`runas`) | `windows-medic-elevated.exe` next to the interpreter | typed recipe arguments (`elevation_protocol.py`) | UAC prompt is the consent; the helper accepts one recipe and re-verifies the target itself |

Absent by design and checked by tests: `shell=True` anywhere (`test_layering.py`),
subprocess calls with a command string (`test_execution_surfaces.py`), `os.system`/`exec*`/
`spawn*`/`startfile`, generic PowerShell/shell/command MCP tools (`test_mcp_server.py` pins
the eight tool names), kill-by-name (every controller takes an identity).

## 5. Findings

1. **No arbitrary execution path exists.** Four call sites start or stop processes; each
   targets a fixed executable or an exact, re-verified process handle, and none accepts a
   command, an executable path or a process name from a caller. Enforced by
   `tests/architecture/test_execution_surfaces.py`.
2. **Every mutation is identity-checked twice** (use case revalidation, controller
   `GetProcessTimes` check) and policy-checked before any OS call; every mutation is
   audited before and after.
3. **The only elevated path is one allowlisted recipe** behind a configuration gate that is
   off by default, behind UAC, executed by a helper that trusts nothing it is told — not
   even where to write its result.
4. **Repeated or concurrent MCP calls do not accumulate state**: the stdio server stayed
   within 24 MiB of its warm working set over 192 read calls including a concurrent burst
   (`tests/integration/mcp/test_stdio_server.py::TestRepeatedCalls`).
5. **Residual risk (accepted for v1, made visible):** the elevated helper, its Python
   interpreter and the `windows_medic` package live in the user's own environment (the
   repository's `.venv`), which the user's account can modify. Code already running as
   the same user can therefore replace the helper, and the next UAC prompt the user
   approves runs that code as administrator; the one-recipe guarantee holds only for an
   untampered environment. Mitigations: the DWM recipe is off by default; `windows-medic
   doctor` reports an `elevation` warning whenever it is enabled, naming the helper and
   advising to approve only a UAC prompt the user started; the UAC prompt shows the
   helper's path. Removing the risk needs an administrator-installed helper in a
   protected location (`Program Files`), which conflicts with the unelevated install and
   is listed under later work (`docs/product-spec.md` §17).
   The critical-process list is defence in depth (Windows also refuses), and a renamed
   binary is classified by its image name; both are documented in the product spec.

## 6. Re-review triggers

Re-run this review when: a new `subprocess`/Win32 process call appears (the guard fails),
a new MCP tool is added, an elevated recipe is added, HTTP transport is introduced
(`docs/product-spec.md` §17), or automatic remediation is introduced (product-spec §10).
