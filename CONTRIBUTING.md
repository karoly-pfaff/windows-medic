# Contributing to Windows Medic

Thanks for helping. This document is the engineering contract of the repository: the rules
every change follows, whether a person or an AI coding agent writes it. It also covers the
development setup and the quality gate.

What the product does belongs in [docs/product-spec.md](docs/product-spec.md); the design
and the reasons behind it belong in [docs/architecture.md](docs/architecture.md); work not
built yet is listed under "Later work" in the product spec.

## What Windows Medic is for

A trustworthy local tool that can answer:

- Why is this Windows machine slow now?
- What made it slow recently?
- Which process tree is responsible?
- What owns this port?
- Are stale/orphaned development processes consuming resources?
- Which safe recovery action can fix the problem?
- Can Windows Medic execute that recovery and verify that it worked?

Its primary interactive client is Claude Code through MCP. The MCP layer is an adapter, not
the application: business logic never lives in MCP tool functions.

## Development setup

Requirements: Windows 11, [uv](https://docs.astral.sh/uv/) 0.12 or newer. uv installs the
pinned Python (3.13, see `.python-version`) on demand.

```powershell
git clone https://github.com/karoly-pfaff/windows-medic
cd windows-medic
uv sync --all-groups
```

This installs the project editable into `.venv`, with the same commands an installed copy
has: `windows-medic`, `windows-medic-agent`, `windows-medic-agentw`, `windows-medic-mcp` and
`windows-medic-elevated`. Run them through uv from the checkout:

```powershell
uv run windows-medic health
uv run windows-medic-agent --duration 30   # a bounded agent run, JSON logs on stderr
uv run windows-medic mcp-config            # registers the checkout's MCP server with Claude Code
```

Set `WINDOWS_MEDIC_DATA_DIR` to a scratch directory to keep experiments away from your own
installation; `WINDOWS_MEDIC_LOG_LEVEL` and `WINDOWS_MEDIC_CONFIG_FILE` override the log
level and the configuration file.

To try the MCP server in the MCP Inspector (needs Node.js and `npx`):

```powershell
uv run mcp dev src/windows_medic_mcp/server.py
```

The read tools are harmless; the mutation tools act on your machine exactly as the CLI
does.

## Core engineering principles

1. **Correctness before cleverness.** Diagnostics and repair decisions must be explainable from captured evidence.
2. **Safety before convenience.** Never expose arbitrary shell, arbitrary PowerShell, arbitrary process-kill-by-name, or arbitrary command execution through MCP.
3. **Clean architecture.** Domain and application code must not depend on MCP, psutil, SQLite, subprocess, Windows APIs, Pydantic, or framework code.
4. **Dependency inversion.** Operating-system access, persistence, time, process control, and elevation are ports implemented by adapters.
5. **Deterministic domain logic.** Classification, incident detection, risk assessment, and repair-policy decisions are pure and unit-testable wherever practical.
6. **Explicit identities.** A Windows process is identified by `(pid, create_time)`, never by PID alone. PID reuse must be treated as normal behavior.
7. **Structured data over prose.** Internal use cases return typed models. Human-readable explanations are produced at the boundary.
8. **Least privilege.** Monitoring and normal repairs run unelevated. Elevated behavior is isolated, allowlisted, auditable, and invoked only when necessary.
9. **No speculative repair.** Every suggested repair must reference evidence and a target identity.
10. **Verify mutations.** A repair is not successful because a command returned zero; verify the intended postcondition.
11. **Bounded resource use.** The monitor must not become the workload it is trying to diagnose.
12. **No hidden magic thresholds.** Detection thresholds live in typed configuration with documented defaults.

## Python standards

Target Python 3.13. Use `uv` for environments, dependencies, locking, and command execution.

Required quality tooling:

- Ruff for formatting and linting
- mypy in strict mode
- pytest
- pytest-cov with branch coverage
- Hypothesis for policy/state-machine edge cases where valuable
- import-linter for architecture boundaries

Use modern Python typing. Prefer immutable/frozen dataclasses for domain value objects. Use `Protocol` for application ports unless an abstract base class provides clear value. Use `Enum`/`StrEnum` for closed vocabularies. Avoid untyped dictionaries crossing layers.

Pydantic is permitted at configuration and MCP/serialization boundaries. Do not make domain entities inherit from Pydantic models.

Prefer composition over inheritance. Keep functions and classes focused. Avoid god services, generic `utils.py`, service locators, hidden globals, and mutable module-level state.

Do not introduce an abstraction until it protects a meaningful boundary or removes concrete duplication. Clean architecture is not permission to create one interface per function.

## How the code is organised

One distribution, `windows-medic`, with five import packages under `src/`:

| Package | Role |
| ------- | ---- |
| `windows_medic` | the core library: `domain` (pure policies and models), `application` (use cases and ports), `infrastructure` (Windows, SQLite, configuration adapters) |
| `windows_medic_root` | the composition root: `compose()` wires adapters into use cases |
| `windows_medic_agent` | the background monitor |
| `windows_medic_cli` | the command-line interface |
| `windows_medic_mcp` | the MCP server |

Tests mirror the packages: `tests/unit/` has `domain`, `application` (over fake ports),
`infrastructure`, `root`, `agent`, `cli` and `mcp`; `tests/contract` covers entry points and
packaging, `tests/integration` the real OS and the real MCP stdio server, `tests/soak` the
soak harness.

## Layering rules

Allowed dependency direction:

```text
interfaces/adapters  ->  application  ->  domain
infrastructure       ->  application  ->  domain
```

`domain` imports only Python standard-library modules that do not perform I/O.

`application` may import `domain` and application-owned port definitions. It must not import implementation adapters.

`windows_medic_mcp`, `windows_medic_cli`, `windows_medic_agent`, `infrastructure.windows`, and `infrastructure.persistence` may depend inward but never the reverse. Applications depend on the composition root, the composition root depends on the core, nothing points the other way (`docs/architecture.md` §2).

MCP tool handlers must be thin: validate boundary input, invoke one application use case, map the typed result to an MCP-safe response.

Architecture rules must be enforced by import-linter tests/configuration, not only documented. The import-linter contracts in `pyproject.toml` and the AST guards in `tests/architecture/` run on every gate, and every place that starts or stops a process is allowlisted per module in `tests/architecture/test_execution_surfaces.py`.

## Error handling

Use explicit domain/application error types for expected failures. Examples include stale process identity, protected process, insufficient privilege, port owner changed, repair verification failed, and unavailable metric.

Never use `except Exception: pass`.

Catch broad exceptions only at process/boundary supervision points where they are logged with context and converted into a deliberate failure state.

Do not use exceptions as ordinary branching logic inside classification policies.

## Windows/process safety rules

Never:

- use `shell=True`;
- concatenate untrusted input into a command string;
- expose a generic shell/PowerShell MCP tool;
- kill a process solely because of its executable name;
- trust PID without validating create time;
- automatically terminate critical Windows processes;
- automatically restart DWM;
- silently elevate privileges;
- consider a mutation successful without postcondition verification.

Maintain a critical-process protection policy. Protection is defense in depth; Windows refusing an operation is not the policy.

Before process mutation, re-resolve the target and verify its `(pid, create_time)` identity. For tree operations, build a fresh tree immediately before execution and report any identity drift.

Commands executed through adapters must use argument arrays or direct OS APIs.

A change to a repair or an execution surface also updates [docs/safety-review.md](docs/safety-review.md).

## Repair model

Every repair recipe declares:

- stable action id;
- risk level (`low`, `medium`, `high`, `critical`);
- whether elevation is required;
- target type;
- preconditions;
- execution steps;
- verification/postcondition;
- rollback or recovery note when meaningful.

High-risk repairs must never be executed as an automatic remediation. DWM recovery is high-risk and explicit-only.

Automatic remediation, if introduced, is limited to explicitly configured low-risk recipes with high-confidence evidence and must be disabled by default until it has been designed, reviewed and tested as a change of its own.

## Monitoring rules

Use adaptive sampling rather than aggressively polling every process at high frequency forever.

Keep normal operation cheap. Escalate sampling when system pressure is detected. Bound in-memory history, persisted history, query result sizes, and log sizes.

Incident records must preserve enough evidence to explain a diagnosis later. Do not store every raw sample forever.

The agent must tolerate process exit, access denied, PID reuse, partial metric availability, and transient Windows API failures without crashing its monitoring loop.

## MCP design rules

Use the official MCP Python SDK v2 and its `MCPServer` API. The initial production transport is stdio for Claude Code.

MCP exposes task-oriented capabilities, not low-level wrappers. Prefer tools such as `diagnose_slowdown` over a dozen metric getters when a single application use case owns the behavior.

Read operations and mutating operations must be visibly distinct in naming and output.

Tool responses must be bounded and structured. Never dump an unbounded process list or log file into model context.

Do not add Streamable HTTP/LAN transport until the local product is correct and the transport has been designed as a change of its own. When HTTP is added, bind to loopback by default and treat LAN exposure as a security feature, not a flag sprinkled into startup code.

## Testing contract

Tests follow the test pyramid:

- domain policy tests: exhaustive unit tests, including edge cases;
- application use-case tests: fake ports, deterministic clock, no Windows dependency;
- adapter contract tests: real adapter behavior where practical;
- Windows integration tests: marked and isolated;
- MCP contract tests: tool schema, input validation, response shape, error mapping;
- end-to-end smoke tests: real server against a controlled test process tree.

Safety-critical domain/application policies should achieve 100% branch coverage. Repository-wide coverage must not regress below the configured gate.

Every bug fix adds a regression test that fails before the fix and passes after it.

Tests must not depend on arbitrary sleeps when a bounded polling/assertion mechanism can verify the condition.

No test may kill unrelated user processes. Integration tests must create and own their target process trees and validate identities before cleanup.

## Quality gate

One command runs everything a change must pass:

```powershell
.\scripts\check-quality.ps1                             # the normal gate
.\scripts\check-quality.ps1 -IncludeWindowsIntegration  # also the real-OS suite
```

It runs these standard commands, stopping at the first failure; keep them stable:

```powershell
uv sync --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run lint-imports
uv run pytest -m "not windows_integration" --cov --cov-branch
uv run pytest -m windows_integration          # with -IncludeWindowsIntegration
```

If a change makes one of these commands inaccurate, update this document, the README,
`scripts/check-quality.ps1` and `.github/workflows/ci.yml` in the same change.

GitHub Actions (`.github/workflows/ci.yml`) runs the gate on every pull request and every
push to `main`, then the Windows integration suite on a fresh `windows-latest` runner. A
pull request is merged only when both are green.

- Branch coverage is enforced (`fail_under` in `pyproject.toml`).
- `windows_integration` tests touch the real OS. They create and own every process they
  act on and never touch anything else.
- Tests that restart the real Explorer or DWM are marked `windows_disruptive` and only run
  on request: `$env:WINDOWS_MEDIC_DISRUPTIVE_TESTS = "1"; uv run pytest -m windows_disruptive`
  (also set `WINDOWS_MEDIC_DWM_TEST = "1"` for the DWM case, which needs UAC).

### Soak and stress

```powershell
uv run python -m tests.soak --minutes 10        # short overhead measurement
uv run python -m tests.soak --hours 2 --churn   # release soak with process churn
uv run pytest -m windows_integration tests/integration/windows/test_stress.py
```

The soak runs the installed agent against a temporary data directory, samples it from the
outside and judges it against the targets: mean CPU below 1 % of the machine, working set
below 100 MiB, no growth between the first and the last quarter. The stress tests generate
bounded, self-terminating load (CPU bursts, one memory allocation sized against free
memory, process and port-owner churn, a hostile SQLite writer) and check that incidents
stay stable and the monitor loop never dies.

## Definition of Done for every change

A change is complete only when:

- acceptance criteria are implemented;
- architecture boundaries remain valid;
- public behavior is typed and documented;
- unit/integration tests appropriate to the change pass;
- Ruff passes;
- mypy strict passes;
- architecture/import checks pass;
- coverage gates pass;
- no temporary TODO, disabled test, broad exception suppression, or debug output remains unless explicitly documented in the relevant doc;
- relevant docs are updated;
- the repository is left runnable from a clean checkout using documented commands.

Do not mark a change complete based on code inspection alone. Run its validation commands.

## Change protocol

Work on one coherent change at a time. For anything larger than a fix, open an issue first
so the design can be agreed before the code is written.

Before implementation:

1. Read the product spec sections the change touches and the relevant architecture sections.
2. Inspect the existing code before making claims about it.
3. Identify the smallest coherent vertical change that satisfies the goal without pre-building later work.

During implementation:

1. Add/adjust tests with the implementation.
2. Keep changes within the scope of the change.
3. Prefer extending existing abstractions over parallel duplicate mechanisms.
4. If the documented architecture is insufficient or wrong, stop the shortcut: update `docs/architecture.md` deliberately, recording the decision and its reason.

After implementation:

1. Run the checks specific to the change.
2. Run the standard quality gate.
3. Update every affected doc.
4. Describe what changed, the verification performed and any remaining known limitation (in the pull request).

Do not defer part of a change silently; anything left for later is said so in the docs.

## Scope discipline

Do not add a GUI, cloud service, accounts, telemetry upload, LLM calls inside the product, Docker, a plugin system, or cross-platform abstractions unless the maintainers explicitly agree to them.

Windows Medic diagnoses Windows. Portable primitives are welcome, but cross-platform support is not a product goal.

Do not build an autonomous optimizer that kills processes based on heuristics. The product gathers evidence, classifies risk, proposes bounded repairs, executes explicit approved actions, and verifies results.

## Documents

- [docs/product-spec.md](docs/product-spec.md): what the product does, its defaults and
  the work not built yet
- [docs/architecture.md](docs/architecture.md): the design and the reasons behind it
- [docs/safety-review.md](docs/safety-review.md): every input boundary, mutation and
  execution surface, and the residual risks
- [docs/testing-strategy.md](docs/testing-strategy.md): what each test layer proves
- [docs/release-checklist.md](docs/release-checklist.md): what must hold before a release
