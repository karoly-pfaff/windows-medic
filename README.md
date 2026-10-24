# Windows Medic

[![CI](https://github.com/karoly-pfaff/windows-medic/actions/workflows/ci.yml/badge.svg)](https://github.com/karoly-pfaff/windows-medic/actions/workflows/ci.yml)

Windows Medic lets Claude Code find out why your Windows machine is slow and fix it safely.

A small background agent watches the machine. When CPU or memory pressure lasts, it records
what was happening and which processes were responsible. Claude Code connects to Windows
Medic over MCP and can then answer questions like these:

- *Why is my machine slow?* / *What made it slow half an hour ago?*
- *What is using port 5173?*
- *Are there leftover dev servers or build processes eating memory?*
- *Explorer is frozen — can you restart it?*

Every answer is built from captured evidence and names the exact processes involved. Every
repair is explicit, checked against a protection policy before anything is touched,
verified afterwards and recorded in an audit log.

Everything stays on your machine: no cloud service, no telemetry, no network access. Windows
Medic has no tool that runs arbitrary commands, scripts or shell input.

## Requirements

- Windows 11 (developed and tested on Windows 11)
- [uv](https://docs.astral.sh/uv/getting-started/installation/) 0.12 or newer. uv
  downloads the Python version Windows Medic needs by itself.
- [Claude Code](https://claude.com/claude-code), to use Windows Medic through Claude

No administrator rights are needed to install or run it.

## Install

```powershell
uv tool install git+https://github.com/karoly-pfaff/windows-medic
windows-medic install-agent
windows-medic doctor
```

- `uv tool install` puts the `windows-medic` commands on your `PATH`. If uv warns that its
  tool directory is not on `PATH`, run `uv tool update-shell` and open a new terminal.
- `install-agent` creates the data directory and a commented `config.toml`. It also
  registers a Task Scheduler task, `WindowsMedic\Agent`, which starts the agent at every
  logon, unelevated and without a window. It starts the agent right away.
- `doctor` checks the installation and says what to do about anything that is not right.

### Connect Claude Code

```powershell
windows-medic mcp-config
```

This prints the exact command for your installation. Run it once to register the server
for all your projects:

```powershell
claude mcp add windows-medic -- "C:\Users\<you>\AppData\Roaming\uv\tools\windows-medic\Scripts\windows-medic-mcp.exe"
```

Instead of registering it for every project, you can save the JSON block it prints as
`.mcp.json` in one project. Then ask Claude something like *"Why is my machine slow?"*.

## Using it with Claude

Claude Code sees eight tools. Five of them only read:

| Tool | What it answers |
| ---- | --------------- |
| `get_system_health` | CPU, memory, commit charge, disk I/O and the top processes right now |
| `diagnose_slowdown` | why the machine is or was slow, as ranked findings with evidence and confidence |
| `inspect_process` | one process: command line, parents and children, protection, risk markers |
| `inspect_port` | which process owns a TCP port, and whether clearing it is allowed |
| `list_recent_incidents` | the recorded episodes of sustained CPU or memory pressure |

Three change something. They are marked as destructive, and Claude Code asks for your
permission before running them unless you have allowed them permanently:

| Tool | What it does |
| ---- | ------------ |
| `terminate_process` | ends one exact process, or a whole process tree |
| `clear_port` | ends the process listening on a port |
| `restart_windows_component` | restarts Explorer (or DWM, if you enabled it) for your session |

What a repair will and will not do:

- **Exact identity only.** A repair names a process by PID *and* creation time, as a read
  tool reported it. If the PID now belongs to a different process, the repair is refused
  instead of hitting the wrong one.
- **Protected processes are never touched.** Critical Windows processes, Windows
  components, Windows Medic itself and anything you add to the protection list are refused
  before any system call. A tree that contains a protected process is refused as a whole.
- **Verified.** A repair counts as successful only once the process is observed to be
  gone, or the port free, or a new Explorer running. Survivors and processes that appeared
  in the meantime are reported.
- **Audited.** Every attempt is recorded, including refusals: `windows-medic repairs`
  lists them.
- **Never automatic.** Windows Medic diagnoses on its own but repairs only when asked.

Restarting DWM (the desktop compositor) makes the screen flicker and needs administrator
rights. It is therefore off by default. If you turn it on with
`[repairs] high_risk_repairs_enabled = true`, each restart asks for a UAC confirmation.
Only approve a prompt for a restart you asked for; `windows-medic doctor` explains why.

## Command line

The same capabilities are available without Claude:

```powershell
windows-medic health                        # what the machine is doing right now
windows-medic diagnose --since-minutes 30   # why it is (or was) slow
windows-medic incidents --limit 10          # recorded pressure episodes, newest first
windows-medic inspect 1234                  # one process, its tree and protection
windows-medic port 5173                     # who owns a port
windows-medic terminate 1234 --create-time 2026-09-11T09:00:02+00:00 [--tree]
windows-medic clear-port 3000
windows-medic restart-component explorer
windows-medic repairs --limit 10            # the repair audit
```

`terminate` needs the exact creation time that `inspect` or `diagnose` prints. Every command
supports `--help`.

## How it works

- **The agent** samples the system every 2 seconds and the process list every 10 seconds
  (every 2 seconds while pressure builds up). It keeps a 30-minute rolling window in memory
  with hard size limits. On a typical workstation it uses well under 1 % CPU and about
  50 MiB of memory.
- **Incidents.** CPU at 90 % or more for 20 seconds, or memory 90 % used or under 1.5 GiB
  free for 20 seconds, opens an incident. The incident keeps the samples from just before
  it started and the processes that contributed most, and is stored for 7 days. If
  monitoring stops in the middle of an incident (reboot, logoff), the incident is marked
  interrupted rather than left "ongoing".
- **Diagnosis** combines recent incidents, a fresh measurement and Windows' own
  "not responding" verdicts into ranked findings: CPU or memory pressure, resource hogs,
  hung windows and stale development process trees. Each finding states its evidence,
  what raised or lowered its confidence, and which repairs would apply. A process is
  called stale only on validated parent evidence, never because of its name.

## Configuration

All settings have defaults and can be changed in
`%LOCALAPPDATA%\WindowsMedic\config.toml`:

```powershell
windows-medic config init     # write config.toml with every setting commented at its default
windows-medic config check    # show where settings come from and the values in force
```

For example:

```toml
[pressure]
cpu_percent = 85              # open a CPU incident at 85 % instead of 90 %

[protection]
additional_protected_names = ["backup-agent.exe"]   # never terminate these

[repairs]
high_risk_repairs_enabled = false                   # DWM restart through UAC
```

Every program reads the configuration when it starts. The CLI and the MCP server (which
Claude Code starts per session) pick up a change by themselves. The agent needs a restart:
run `windows-medic uninstall-agent --stop` and then `windows-medic install-agent`, or log
off and on again. An invalid value stops the program at startup with a message naming the
setting.

## Files

Everything lives in `%LOCALAPPDATA%\WindowsMedic` (set `WINDOWS_MEDIC_DATA_DIR` to use
another directory):

| Path | Contents |
| ---- | -------- |
| `config.toml` | your configuration |
| `incidents.sqlite3` | incidents and the repair audit |
| `logs\windows-medic-agent.log` | the agent's log, rotated at 5 MiB, 3 files kept |
| `elevated\` | results of DWM restarts through UAC |

`windows-medic status` shows the locations, whether the agent is running and the latest
records.

## Update

```powershell
windows-medic uninstall-agent --stop
uv tool upgrade windows-medic
windows-medic install-agent
```

Stopping the agent first lets uv replace its files. Your configuration and history are
kept.

## Uninstall

```powershell
windows-medic uninstall-agent --stop                # remove the logon task, stop the agent
windows-medic uninstall-agent --stop --purge-data   # ... and delete Windows Medic's data
claude mcp remove windows-medic
uv tool uninstall windows-medic
```

`--purge-data` deletes only the files Windows Medic created. If the data directory also
holds other files, they and the directory are kept.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the engineering rules
every change follows, the quality gate and how the code is organised.

## License

[MIT](LICENSE) © Károly Pfaff
