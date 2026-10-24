# v1 release checklist

A release is the commit at which every item below is checked with fresh evidence. Items
marked *manual* cannot run in the automatic gate (they restart the real shell, need UAC,
or take hours); their evidence is recorded here with the numbers.

## Automatic gate

- [x] `.\scripts\check-quality.ps1 -IncludeWindowsIntegration` passes from a clean checkout
      (`uv sync --all-groups`, ruff format/check, mypy strict, import-linter, unit +
      contract suite with branch coverage ≥ 90 %, Windows integration suite).
- [ ] Both CI jobs (`.github/workflows/ci.yml`: quality gate, Windows integration) are
      green on the release commit, on a fresh GitHub-hosted runner.
- [x] Architecture guards: domain purity, no `shell=True`, closed execution surfaces
      (`tests/architecture/test_execution_surfaces.py`), import-linter contracts.
- [x] MCP contract: eight tools, bounded structured responses, `isError` for invalid
      input, repeated/concurrent calls bounded (`tests/integration/mcp/test_stdio_server.py`).
- [x] Failure hardening (`tests/integration/windows/test_stress.py`): repeated CPU
      pressure transitions, bounded memory pressure, process churn, port-owner churn,
      agent killed mid-write, hostile SQLite writer.

## Manual verification (recorded)

- [x] **Soak, 2 h, default configuration, development workstation** (18 logical CPUs,
      31 GiB, ~420 processes),
      `uv run python -m tests.soak --hours 2 --sample-interval 10`: 651 samples; agent CPU
      mean 0.025 % of the machine (p95 0.050 %, max 0.094 %); working set 47.8 → 48.6 MiB
      between the first and last quarter (max 48.6 MiB, private max 35.1 MiB); handles and
      threads flat; 0 collector failures, 0 overruns, 0 persist failures; the machine slept
      for an hour mid-run and the agent resumed cleanly. Verdict PASS against the targets:
      mean agent CPU < 1 % of the machine, working set < 100 MiB, growth ≤ 16 MiB between
      the first and last quarter, no collector failures.
- [x] **Soak finding acted on** — the first soak run showed the working set growing by
      ~1.5 MiB per process snapshot towards a ~270 MiB plateau because 240 full process
      snapshots (30 min) were retained while the incident engine reads only the last two;
      `[history] max_process_snapshots` now defaults to 12.
- [ ] **Explorer restart on a real desktop** (*manual, disruptive*):
      `WINDOWS_MEDIC_DISRUPTIVE_TESTS=1 uv run pytest -m windows_disruptive -k explorer`
      — run by the releasing person on their own session; expected: a new `explorer.exe`
      instance is verified and the taskbar returns.
- [ ] **DWM restart through UAC** (*manual, disruptive*):
      `WINDOWS_MEDIC_DISRUPTIVE_TESTS=1 WINDOWS_MEDIC_DWM_TEST=1 uv run pytest -m windows_disruptive -k dwm`
      with `[repairs] high_risk_repairs_enabled = true` — expected: one UAC prompt, the
      screen flickers, a new `dwm.exe` is verified, the audit record shows the replacement.
- [ ] **Clean-machine install** (*manual*): on a machine without the repository,
      follow README "Install"; expected: `windows-medic doctor` reports every
      check `[ok]`, the logon task exists in Task Scheduler under `WindowsMedic\Agent`, the
      agent survives a logoff/logon and `windows-medic status` shows it running.
- [ ] **Claude Code end to end** (*manual*): register the server with
      `windows-medic mcp-config`, ask Claude "why is my machine slow?" and "what owns port
      N?"; expected: structured answers from `diagnose_slowdown`/`inspect_port`, and a
      mutation tool refuses a protected target with a `rejection`, not an error.

## Documents current at release

- [x] `README.md` (install, Claude Code, commands, configuration, update, uninstall)
- [x] `CONTRIBUTING.md` (development setup, quality gate, soak and stress, code layout)
- [x] `docs/product-spec.md` (behaviour), `docs/architecture.md` (design)
- [x] `docs/safety-review.md` (execution and repair surfaces)
- [x] `docs/testing-strategy.md` (includes soak and stress)

## Cutting the release

1. Run the automatic gate on a clean checkout and paste the summary line into the commit.
2. Complete the manual items above on the releasing machine; record the outcome.
3. Bump `version` in `pyproject.toml` and `windows_medic.__version__` together
   (`tests/contract/test_packaging.py::test_the_version_is_declared_once_and_matches_the_package`
   guards it).
4. Tag the commit `v<version>`.
