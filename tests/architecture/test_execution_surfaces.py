"""Every way the product can start or stop a process is enumerated here, on purpose.

The safety review (docs/safety-review.md) reasons about a closed list of execution
surfaces. This guard keeps the list closed: a new call site fails until it is reviewed and
added below, and an entry that disappears from the code fails too, so the list never goes
stale.
"""

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"
# Every import package the scans must cover lives directly under SOURCE_ROOT.
PACKAGES = {
    "windows_medic",
    "windows_medic_root",
    "windows_medic_agent",
    "windows_medic_cli",
    "windows_medic_mcp",
}

# Fully qualified callee names (as written in the source) that start or stop processes.
_PROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "os.system",
        "os.popen",
        "os.startfile",
        "os.kill",
        "os.execv",
        "os.execve",
        "os.execl",
        "os.execlp",
        "os.execvp",
        "os.execvpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnl",
        "os.spawnlp",
    }
)
# Win32 entry points reached through ctypes; matched as attribute calls (``dll.Name(...)``)
# so that a Python class that happens to share a name, e.g. the TerminateProcess use case,
# is not mistaken for the API.
_WIN32_CALLS = frozenset(
    {
        "ShellExecuteExW",
        "ShellExecuteExA",
        "ShellExecuteW",
        "ShellExecuteA",
        "CreateProcessW",
        "CreateProcessA",
        "CreateProcessAsUserW",
        "CreateProcessWithLogonW",
        "WinExec",
        "TerminateProcess",
        "NtTerminateProcess",
    }
)

# The reviewed surfaces: module (relative to its package's src) -> callees it may use. Each
# is one fixed executable or one exact process handle; none accepts a command string from a
# caller. All four live in the core library; the composition root and the applications
# start nothing themselves.
ALLOWED_SURFACES: dict[str, frozenset[str]] = {
    # %SystemRoot%\explorer.exe only (Explorer recovery), argument array, detached.
    "windows_medic/infrastructure/windows/component_controller.py": frozenset({"subprocess.Popen"}),
    # %SystemRoot%\System32\schtasks.exe only (logon task), argument array, no window.
    "windows_medic/infrastructure/windows/task_scheduler.py": frozenset({"subprocess.run"}),
    # windows-medic-elevated.exe only (UAC), typed recipe arguments, result file.
    "windows_medic/infrastructure/windows/elevation_launcher.py": frozenset({"ShellExecuteExW"}),
    # One exact (pid, create_time) after re-checking the create time on the open handle.
    "windows_medic/infrastructure/windows/process_controller.py": frozenset({"TerminateProcess"}),
}


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return node.attr if prefix is None else f"{prefix}.{node.attr}"
    return None


def _callee(call: ast.Call) -> str | None:
    """The reviewed name of a call: a known dotted name, or a bare Win32 attribute."""
    dotted = _dotted(call.func)
    if dotted is None:
        return None
    if dotted in _PROCESS_CALLS:
        return dotted
    if isinstance(call.func, ast.Attribute) and call.func.attr in _WIN32_CALLS:
        return call.func.attr
    return None


def execution_call_sites(src_root: Path) -> list[tuple[str, int, str]]:
    """``(relative path, line, callee)`` for every process start/stop call under *src_root*."""
    sites: list[tuple[str, int, str]] = []
    for path in sorted(src_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                callee = _callee(node)
                if callee is not None:
                    sites.append((path.relative_to(src_root).as_posix(), node.lineno, callee))
    return sites


def string_command_calls(src_root: Path) -> list[tuple[str, int]]:
    """Subprocess calls whose command is a string (literal or f-string) instead of an array."""
    hits: list[tuple[str, int]] = []
    for path in sorted(src_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            callee = _dotted(node.func)
            if callee not in _PROCESS_CALLS or not callee.startswith("subprocess."):
                continue
            if node.args and isinstance(node.args[0], (ast.Constant, ast.JoinedStr)):
                hits.append((path.relative_to(src_root).as_posix(), node.lineno))
    return hits


def all_execution_call_sites() -> list[tuple[str, int, str]]:
    assert {p.name for p in SOURCE_ROOT.iterdir() if (p / "__init__.py").is_file()} == PACKAGES
    return execution_call_sites(SOURCE_ROOT)


class TestExecutionSurfacesAreClosed:
    def test_every_call_site_is_a_reviewed_surface(self) -> None:
        unexpected = [
            site
            for site in all_execution_call_sites()
            if site[2] not in ALLOWED_SURFACES.get(site[0], frozenset())
        ]

        assert unexpected == [], (
            "new process start/stop call sites need a safety review before being allowed: "
            f"{unexpected}"
        )

    def test_every_reviewed_surface_still_exists(self) -> None:
        present = {(path, callee) for path, _, callee in all_execution_call_sites()}
        expected = {
            (path, callee) for path, callees in ALLOWED_SURFACES.items() for callee in callees
        }

        assert expected <= present, f"stale allowlist entries: {sorted(expected - present)}"

    def test_no_subprocess_call_takes_a_command_string(self) -> None:
        assert string_command_calls(SOURCE_ROOT) == []


def _write_module(root: Path, relative: str, body: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


class TestGuardItself:
    def test_finds_stdlib_and_win32_call_sites(self, tmp_path: Path) -> None:
        # Source text the guard must flag; it is parsed, never executed.
        _write_module(
            tmp_path,
            "pkg/a.py",
            "import subprocess, os, ctypes\n"
            "subprocess.run(['x'])\n"
            "os.system('dir')\n"
            "ctypes.WinDLL('kernel32').TerminateProcess(1, 0)\n"
            "shell32.ShellExecuteExW(info)\n"
            "print('not a process call')\n",
        )

        assert execution_call_sites(tmp_path) == [
            ("pkg/a.py", 2, "subprocess.run"),
            ("pkg/a.py", 3, "os.system"),
            ("pkg/a.py", 4, "TerminateProcess"),
            ("pkg/a.py", 5, "ShellExecuteExW"),
        ]

    def test_flags_string_commands_but_not_arrays(self, tmp_path: Path) -> None:
        _write_module(
            tmp_path,
            "pkg/b.py",
            "import subprocess\n"
            "subprocess.run('dir')\n"
            "subprocess.Popen(f'del {x}')\n"
            "subprocess.run(['dir'])\n"
            "subprocess.run(command)\n",
        )

        assert string_command_calls(tmp_path) == [("pkg/b.py", 2), ("pkg/b.py", 3)]
