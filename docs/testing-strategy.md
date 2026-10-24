# Testing strategy — Windows Medic

## Goals

Tests must prove diagnostic correctness, process-identity safety, repair targeting, architecture boundaries, and bounded resource behavior.

## Test categories

### Domain unit tests

Pure tests for process identity, pressure state machines, protection policy, classifier confidence, risk policy, and incident lifecycle.

Use table-driven pytest cases and Hypothesis where state/race combinations are valuable.

Safety-critical policies target 100% branch coverage.

### Application tests

Use fake ports and a deterministic clock. Exercise use cases without psutil, Windows APIs, SQLite, or MCP.

Important race cases:

- PID reused between plan and execution;
- owner changes between inspect-port and clear-port;
- parent PID reused;
- process exits mid-inspection;
- tree membership changes before mutation;
- protected child appears in a target tree;
- repair mechanism reports success but postcondition fails.

### Adapter contract tests

Each infrastructure adapter has tests proving its contract independent of application policy.

### Windows integration tests

Marked `windows_integration`.

Create only test-owned child processes/listeners. Store exact identities. Cleanup validates identity before termination.

Never target system processes in automated tests.

### Persistence tests

Use temporary SQLite databases. Cover migration, WAL setup, round-trip, retention, partial/busy behavior, and repair audit.

### MCP contract tests

Verify tool names, schemas, input constraints, bounded response mapping, and error mapping using the official SDK client/test facilities where suitable.

### End-to-end smoke tests

Start a controlled process tree/listener, run the real application/MCP path, diagnose it, perform an allowed repair, and verify OS state.

### Stress and failure hardening

Marked `windows_integration`, in `tests/integration/windows/test_stress.py`: repeated CPU pressure transitions (self-terminating burner children, threshold placed between the measured baseline and full load), a bounded memory allocation against a floor derived from what the machine can spare, rapid process churn while the monitor runs, port-owner churn against `inspect_port`, an agent killed mid-write, and a hostile SQLite writer. Load generators live in `tests/soak/stress.py`; every child is test-owned and killed on exit. A scenario that cannot get a clean signal (machine already busy, too little free memory) skips instead of guessing.

`tests/integration/mcp/test_stdio_server.py::TestRepeatedCalls` drives one stdio session through many sequential and concurrent reads and bounds the server's working-set growth and response sizes.

### Soak

`uv run python -m tests.soak --hours 2` runs the installed agent against a temporary data directory and samples its CPU share, working set, private bytes, handles and threads from outside (psutil); the agent's own `agent.health` records are read from its log file. The verdict (`tests/soak/harness.py::judge`, unit-tested) applies the product-spec §14 targets plus growth bounds between the first and last quarter of the run. Reports are JSON and rewritten after every sample. Soak results are evidence for the release checklist, not part of the automatic gate; `--churn` adds background process churn.

### Architecture guards

`tests/architecture/` runs on every gate: domain purity (AST), `shell=True` (AST, over all of `src`), the closed list of process start/stop call sites with a per-module allowlist and a ban on string commands (`test_execution_surfaces.py`), and the import-linter contracts across the five packages. `tests/contract/test_packaging.py` pins the distribution itself: the five packages it builds, one version, type information in every package, every script resolving to a callable, the declared licence.

## Quality gates

Required on normal development:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run lint-imports
uv run pytest -m "not windows_integration" --cov --cov-branch
```

Windows integration gate:

```bash
uv run pytest -m windows_integration
```

Do not use coverage exclusions to hide difficult safety code. Exclusions require an explicit rationale.

## Manual tests

Some disruptive Windows-shell behavior, especially real DWM restart, belongs in an explicit manual test checklist rather than automatic CI.
