"""Render ``config.toml`` text from the typed settings.

:func:`render_default_config` writes every section and key of :class:`Settings`,
commented, with its default value, so a user can uncomment what they want to change
without reading source. :func:`render_effective_config` writes the values actually in
force, for ``windows-medic config check``. Both are generated from the models, so they
cannot drift from what ``load_settings`` accepts.
"""

from enum import Enum
from pathlib import Path

from pydantic import BaseModel

from windows_medic.infrastructure.config.settings import Settings

_DERIVED_KEYS = frozenset({"data_dir", "config_file", "windows_directory"})


def render_default_config() -> str:
    """The default configuration as TOML with every key commented out."""
    settings = Settings(data_dir=Path("C:\\"))
    lines = [
        "# Windows Medic configuration.",
        "# Every key is optional; a commented line shows its built-in default.",
        "# Location: %LOCALAPPDATA%\\WindowsMedic\\config.toml (or WINDOWS_MEDIC_CONFIG_FILE).",
        "#",
        "# data_dir and windows_directory are derived from the environment; set them here",
        "# only to override that:",
        '# data_dir = "C:\\\\Users\\\\you\\\\AppData\\\\Local\\\\WindowsMedic"',
        '# windows_directory = "C:\\\\Windows"',
    ]
    lines.extend(_section_lines(settings, prefix="# ", with_docs=True))
    return "\n".join(lines) + "\n"


def render_effective_config(settings: Settings) -> str:
    """The values in force as TOML, derived keys first."""
    lines = [
        f"data_dir = {_toml(str(settings.data_dir))}",
        f"windows_directory = {_toml(str(settings.windows_directory))}",
    ]
    lines.extend(_section_lines(settings, prefix="", with_docs=False))
    return "\n".join(lines) + "\n"


def _section_lines(settings: Settings, *, prefix: str, with_docs: bool) -> list[str]:
    lines: list[str] = []
    for name in Settings.model_fields:
        if name in _DERIVED_KEYS:
            continue
        section = getattr(settings, name)
        if not isinstance(section, BaseModel):
            continue
        lines.append("")
        lines.append(f"[{name}]")
        doc = (type(section).__doc__ or "").strip().replace("``", "")
        if with_docs and doc:
            lines.append(f"# {doc}")
        for key in type(section).model_fields:
            lines.append(f"{prefix}{key} = {_toml(getattr(section, key))}")
    return lines


def _toml(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Enum):
        return _toml(value.value)
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (tuple, list)):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    raise TypeError(f"unsupported default value {value!r}")
