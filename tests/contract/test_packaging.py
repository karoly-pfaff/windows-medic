"""Packaging contract: one distribution with five import packages.

The core library, the composition root and three applications ship together as
``windows-medic``. Every package carries type information, every console script resolves
to a callable, and the external dependencies stay where the layering says they belong.
"""

import importlib
import tomllib
from pathlib import Path
from typing import Any

import pytest

import windows_medic

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"

PACKAGES = (
    "windows_medic",
    "windows_medic_root",
    "windows_medic_agent",
    "windows_medic_cli",
    "windows_medic_mcp",
)
EXPECTED_SCRIPTS = {
    "windows-medic": "windows_medic_cli.main:main",
    "windows-medic-agent": "windows_medic_agent.main:main",
    "windows-medic-mcp": "windows_medic_mcp.server:main",
    "windows-medic-elevated": "windows_medic.infrastructure.windows.elevation_helper:main",
}
EXPECTED_GUI_SCRIPTS = {"windows-medic-agentw": "windows_medic_agent.main:main"}
LAYER_PACKAGES = (
    "windows_medic",
    "windows_medic.domain",
    "windows_medic.domain.models",
    "windows_medic.domain.policies",
    "windows_medic.application",
    "windows_medic.application.ports",
    "windows_medic.application.use_cases",
    "windows_medic.application.services",
    "windows_medic.infrastructure",
    "windows_medic.infrastructure.windows",
    "windows_medic.infrastructure.persistence",
    "windows_medic.infrastructure.config",
    "windows_medic.infrastructure.observability",
    "windows_medic.infrastructure.time",
    *PACKAGES[1:],
)


def _project() -> dict[str, Any]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        document = tomllib.load(handle)
    assert isinstance(document, dict)
    return document


def test_one_distribution_builds_exactly_the_five_packages() -> None:
    document = _project()

    assert document["project"]["name"] == "windows-medic"
    assert document["tool"]["uv"]["build-backend"]["module-name"] == list(PACKAGES)
    assert "workspace" not in document["tool"]["uv"]
    assert sorted(p.name for p in SRC.iterdir() if (p / "__init__.py").is_file()) == sorted(
        PACKAGES
    )


def test_the_version_is_declared_once_and_matches_the_package() -> None:
    assert _project()["project"]["version"] == windows_medic.__version__


@pytest.mark.parametrize("package", LAYER_PACKAGES)
def test_layer_package_is_importable(package: str) -> None:
    module = importlib.import_module(package)

    assert module.__name__ == package


@pytest.mark.parametrize("package", PACKAGES)
def test_package_ships_type_information(package: str) -> None:
    module = importlib.import_module(package)
    assert module.__file__ is not None

    assert (Path(module.__file__).parent / "py.typed").is_file()


def test_console_and_gui_scripts_resolve_to_callables() -> None:
    project = _project()["project"]

    assert project["scripts"] == EXPECTED_SCRIPTS
    assert project["gui-scripts"] == EXPECTED_GUI_SCRIPTS
    for target in (*EXPECTED_SCRIPTS.values(), *EXPECTED_GUI_SCRIPTS.values()):
        module_name, attribute = target.split(":")
        assert callable(getattr(importlib.import_module(module_name), attribute))


def test_the_license_is_declared_and_shipped() -> None:
    project = _project()["project"]

    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert (REPO_ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")
