"""Architecture guards.

Two independent mechanisms protect the dependency direction:

* an AST scan (this module) that proves ``windows_medic.domain`` imports nothing outside the
  domain except a short allowlist of pure, non-I/O standard-library modules, plus a scan
  for the forbidden ``shell=True`` pattern anywhere under ``src``;
* the import-linter contracts in ``pyproject.toml``, executed here in-process so the
  ordinary test run fails when a contract breaks.

The scanners are exercised against synthetic violating packages so a silently broken
guard cannot pass as "no violations".
"""

import ast
import subprocess
import sys
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_SRC = REPO_ROOT / "src"
SOURCE_ROOT = REPO_ROOT / "src"
# Every import package the scans must cover lives directly under SOURCE_ROOT.
PACKAGES = {
    "windows_medic",
    "windows_medic_root",
    "windows_medic_agent",
    "windows_medic_cli",
    "windows_medic_mcp",
}
PACKAGE = "windows_medic"

# Standard-library modules the domain may import: pure data/algorithm modules only.
# Extending this list is an architecture decision; I/O-capable modules never belong here.
DOMAIN_ALLOWED_STDLIB = frozenset(
    {
        "__future__",
        "abc",
        "bisect",
        "collections",
        "copy",
        "dataclasses",
        "datetime",
        "decimal",
        "enum",
        "fractions",
        "functools",
        "heapq",
        "ipaddress",
        "itertools",
        "math",
        "numbers",
        "operator",
        "re",
        "statistics",
        "string",
        "types",
        "typing",
        "uuid",
    }
)


@dataclass(frozen=True, slots=True)
class ImportViolation:
    module: str
    imported: str
    line: int


def iter_modules(package_dir: Path, package_name: str) -> Iterator[tuple[str, Path]]:
    """Yield ``(dotted module name, path)`` for every module under *package_dir*."""
    for path in sorted(package_dir.rglob("*.py")):
        parts = [package_name, *path.relative_to(package_dir).with_suffix("").parts]
        if parts[-1] == "__init__":
            parts.pop()
        yield ".".join(parts), path


def imported_modules(module_name: str, path: Path) -> Iterator[tuple[str, int]]:
    """Yield absolute dotted names imported by the module at *path*, with line numbers."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom):
            for imported in _resolve_import_from(module_name, path, node):
                yield imported, node.lineno


def _resolve_import_from(module_name: str, path: Path, node: ast.ImportFrom) -> list[str]:
    if node.level == 0:
        return [node.module or ""]
    package_parts = module_name.split(".")
    if path.name != "__init__.py":
        package_parts = package_parts[:-1]
    base = package_parts[: len(package_parts) - (node.level - 1)]
    if node.module:
        return [".".join([*base, node.module])]
    # `from .. import name` can only import submodules/attributes of the base package.
    return [".".join([*base, alias.name]) for alias in node.names]


def is_allowed_for_domain(imported: str, domain_package: str) -> bool:
    if imported == domain_package or imported.startswith(f"{domain_package}."):
        return True
    return imported.split(".", maxsplit=1)[0] in DOMAIN_ALLOWED_STDLIB


def domain_violations(src_root: Path, package: str) -> list[ImportViolation]:
    domain_package = f"{package}.domain"
    return [
        ImportViolation(module_name, imported, line)
        for module_name, path in iter_modules(src_root / package / "domain", domain_package)
        for imported, line in imported_modules(module_name, path)
        if not is_allowed_for_domain(imported, domain_package)
    ]


def shell_true_calls(src_root: Path) -> list[tuple[str, int]]:
    """Return ``(path, line)`` for every call passing ``shell=True``."""
    hits: list[tuple[str, int]] = []
    for path in sorted(src_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                value = keyword.value
                if (
                    keyword.arg == "shell"
                    and isinstance(value, ast.Constant)
                    and value.value is True
                ):
                    hits.append((str(path.relative_to(src_root)), node.lineno))
    return hits


def _write_module(root: Path, dotted: str, body: str) -> None:
    parts = dotted.split(".")
    directory = root.joinpath(*parts[:-1])
    directory.mkdir(parents=True, exist_ok=True)
    for depth in range(1, len(parts)):
        (root.joinpath(*parts[:depth]) / "__init__.py").touch()
    (directory / f"{parts[-1]}.py").write_text(body, encoding="utf-8")


class TestDomainPurityGuard:
    def test_real_domain_imports_only_itself_and_pure_stdlib(self) -> None:
        assert (CORE_SRC / PACKAGE / "domain").is_dir()
        assert domain_violations(CORE_SRC, PACKAGE) == []

    @pytest.mark.parametrize(
        ("statement", "flagged"),
        [
            ("from pkg.infrastructure.windows import reader", "pkg.infrastructure.windows"),
            ("import pkg.interfaces.mcp.server", "pkg.interfaces.mcp.server"),
            ("from pkg.application.ports import clock", "pkg.application.ports"),
            ("from mcp.server.mcpserver import MCPServer", "mcp.server.mcpserver"),
            ("import psutil", "psutil"),
            ("import sqlite3", "sqlite3"),
            ("import subprocess", "subprocess"),
            ("import os.path", "os.path"),
            ("from pydantic import BaseModel", "pydantic"),
            ("from ... import infrastructure", "pkg.infrastructure"),
            ("from ...interfaces import cli", "pkg.interfaces"),
        ],
    )
    def test_guard_flags_outward_and_io_imports(
        self, tmp_path: Path, statement: str, flagged: str
    ) -> None:
        _write_module(tmp_path, "pkg.domain.policies.pressure", f"{statement}\n")

        violations = domain_violations(tmp_path, "pkg")

        assert violations == [ImportViolation("pkg.domain.policies.pressure", flagged, 1)]

    def test_guard_accepts_domain_internal_and_pure_stdlib_imports(self, tmp_path: Path) -> None:
        _write_module(
            tmp_path,
            "pkg.domain.policies.pressure",
            "from dataclasses import dataclass\n"
            "from collections.abc import Sequence\n"
            "from pkg.domain.models.process import ProcessIdentity\n"
            "from . import protection\n"
            "from ..models import samples\n",
        )

        assert domain_violations(tmp_path, "pkg") == []

    def test_guard_resolves_relative_imports_inside_package_init(self, tmp_path: Path) -> None:
        _write_module(tmp_path, "pkg.domain.policies.__init__", "from .pressure import x\n")
        _write_module(tmp_path, "pkg.domain.policies.pressure", "x = 1\n")

        assert domain_violations(tmp_path, "pkg") == []


class TestShellTrueGuard:
    def test_real_source_never_passes_shell_true(self) -> None:
        assert {p.name for p in SOURCE_ROOT.iterdir() if (p / "__init__.py").is_file()} == PACKAGES
        assert shell_true_calls(SOURCE_ROOT) == []

    def test_guard_flags_shell_true_keyword(self, tmp_path: Path) -> None:
        _write_module(
            tmp_path,
            "pkg.infrastructure.runner",
            'import subprocess\n\n\ndef run() -> None:\n    subprocess.run("dir", shell=True)\n',
        )

        assert shell_true_calls(tmp_path) == [(str(Path("pkg/infrastructure/runner.py")), 5)]

    def test_guard_ignores_shell_false(self, tmp_path: Path) -> None:
        _write_module(
            tmp_path,
            "pkg.infrastructure.runner",
            'import subprocess\n\nsubprocess.run(["dir"], shell=False)\n',
        )

        assert shell_true_calls(tmp_path) == []


class TestImportLinterContracts:
    def test_all_contracts_hold(self) -> None:
        # Run in a subprocess: import-linter reconfigures logging via dictConfig, which
        # would disable this process's existing loggers and corrupt later tests.
        program = (
            "import sys; from importlinter.cli import lint_imports; "
            "sys.exit(lint_imports(no_cache=True, no_logo=True))"
        )
        completed = subprocess.run(
            [sys.executable, "-c", program],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )

        assert completed.returncode == 0, completed.stdout + completed.stderr

    def test_domain_contract_forbids_infrastructure_interfaces_and_mcp(self) -> None:
        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            contracts = tomllib.load(handle)["tool"]["importlinter"]["contracts"]

        domain_contracts = [
            contract
            for contract in contracts
            if contract.get("source_modules") == [f"{PACKAGE}.domain"]
        ]
        assert len(domain_contracts) == 1
        forbidden = set(domain_contracts[0]["forbidden_modules"])
        assert {
            f"{PACKAGE}.infrastructure",
            f"{PACKAGE}.application",
            "windows_medic_agent",
            "windows_medic_cli",
            "windows_medic_mcp",
            "mcp",
            "psutil",
            "pydantic",
            "sqlite3",
            "subprocess",
        } <= forbidden
