"""Typed configuration with safe defaults.

Settings are assembled from three layers; later layers win:

1. built-in defaults taken from ``docs/product-spec.md`` (sections 6, 7 and 13);
2. a TOML config file, by default ``<data_dir>/config.toml``;
3. narrow environment overrides intended for development and testing:
   ``WINDOWS_MEDIC_DATA_DIR``, ``WINDOWS_MEDIC_LOG_LEVEL`` and ``WINDOWS_MEDIC_CONFIG_FILE``.

Loading happens once, at the composition root. Domain and application code never read
environment variables or files; they receive typed values.

Every configuration problem is reported as :class:`ConfigurationError` with a message that
names the offending key so the user can fix it without reading source code.
"""

import tomllib
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

DATA_DIR_NAME = "WindowsMedic"
CONFIG_FILE_NAME = "config.toml"
DEFAULT_WINDOWS_DIRECTORY = "C:\\Windows"

ENV_DATA_DIR = "WINDOWS_MEDIC_DATA_DIR"
ENV_LOG_LEVEL = "WINDOWS_MEDIC_LOG_LEVEL"
ENV_CONFIG_FILE = "WINDOWS_MEDIC_CONFIG_FILE"

# Executable names that commonly belong to development tooling. This list is only a hint
# for later classification; a name match on its own never justifies a destructive action.
DEFAULT_DEVELOPMENT_PROCESS_NAMES: tuple[str, ...] = (
    "node.exe",
    "esbuild.exe",
    "headless_shell.exe",
    "python.exe",
    "pythonw.exe",
    "uv.exe",
    "dotnet.exe",
    "java.exe",
    "cargo.exe",
    "rustc.exe",
    "go.exe",
    "deno.exe",
    "bun.exe",
)


# Path/command-line components that identify development tooling regardless of the host
# executable (``npm`` runs as node.exe, Playwright's browsers live under ``ms-playwright``).
DEFAULT_DEVELOPMENT_COMMAND_MARKERS: tuple[str, ...] = (
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "vite",
    "esbuild",
    "webpack",
    "tsc",
    "ts-node",
    "tsx",
    "nodemon",
    "jest",
    "vitest",
    "playwright",
    "ms-playwright",
    "chromium",
    "pytest",
    "uvicorn",
    "flask",
    "jupyter",
)


class ConfigurationError(Exception):
    """Configuration could not be loaded or is invalid. The message is actionable."""


class LogLevel(StrEnum):
    """Closed vocabulary of supported log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class SamplingSettings(_FrozenModel):
    """Sampling intervals and adaptive-escalation bounds, in seconds."""

    system_interval_seconds: float = Field(default=2.0, gt=0, le=60)
    process_interval_seconds: float = Field(default=10.0, gt=0, le=300)
    pressure_process_interval_seconds: float = Field(default=2.0, gt=0, le=60)
    pressure_escalation_max_seconds: float = Field(default=300.0, gt=0, le=3600)
    pressure_cooldown_seconds: float = Field(default=60.0, ge=0, le=3600)

    @model_validator(mode="after")
    def _escalation_is_not_slower_than_normal_sampling(self) -> Self:
        if self.pressure_process_interval_seconds > self.process_interval_seconds:
            raise ValueError(
                "pressure_process_interval_seconds must not exceed process_interval_seconds "
                "(escalated sampling is meant to be faster than normal sampling)"
            )
        return self


class PressureThresholds(_FrozenModel):
    """Incident-detection thresholds. Durations are how long a condition must persist."""

    cpu_percent: float = Field(default=90.0, gt=0, le=100)
    cpu_duration_seconds: float = Field(default=20.0, gt=0, le=3600)
    memory_percent: float = Field(default=90.0, gt=0, le=100)
    memory_available_floor_mib: int = Field(default=1536, ge=0)
    memory_duration_seconds: float = Field(default=20.0, gt=0, le=3600)


class HistorySettings(_FrozenModel):
    """Bounds on in-memory evidence and persisted incident history."""

    rolling_window_minutes: int = Field(default=30, ge=1, le=240)
    incident_retention_days: int = Field(default=7, ge=1, le=365)
    # Hard item caps in addition to the time window. System samples are tiny; process
    # snapshots are not (every process, every field: about 1.5 MiB each on a machine with
    # 420 processes), and the incident engine only ever reads the last two, so their cap
    # is a small multiple of that rather than the whole window (soak evidence).
    max_system_samples: int = Field(default=1800, ge=10, le=100_000)
    max_process_snapshots: int = Field(default=12, ge=2, le=5_000)


# Interactive terminals/IDEs: a process under one of these is likely still wanted.
DEFAULT_TERMINAL_PROCESS_NAMES: tuple[str, ...] = (
    "windowsterminal.exe",
    "wt.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "code.exe",
    "conemu64.exe",
    "alacritty.exe",
)


class ClassifierSettings(_FrozenModel):
    """Hints used by process classification policies."""

    development_process_names: tuple[str, ...] = DEFAULT_DEVELOPMENT_PROCESS_NAMES
    development_command_markers: tuple[str, ...] = DEFAULT_DEVELOPMENT_COMMAND_MARKERS
    claude_markers: tuple[str, ...] = ("claude",)
    terminal_process_names: tuple[str, ...] = DEFAULT_TERMINAL_PROCESS_NAMES


class ProtectionSettings(_FrozenModel):
    """User additions to the centralized protected-process policy."""

    additional_protected_names: tuple[str, ...] = ()


class RepairSettings(_FrozenModel):
    """Repair enablement and execution bounds. High-risk repairs are off by default."""

    high_risk_repairs_enabled: bool = False
    verify_timeout_seconds: float = Field(default=5.0, ge=0, le=60)
    verify_interval_seconds: float = Field(default=0.1, gt=0, le=5)
    max_tree_members: int = Field(default=200, ge=1, le=2000)
    audit_retention_days: int = Field(default=30, ge=1, le=365)
    max_audit_list: int = Field(default=50, ge=1, le=500)
    component_verify_timeout_seconds: float = Field(default=15.0, ge=0, le=120)
    component_verify_interval_seconds: float = Field(default=0.25, gt=0, le=5)
    explorer_auto_restart_wait_seconds: float = Field(default=5.0, ge=0, le=60)
    elevation_timeout_seconds: float = Field(default=120.0, ge=1, le=600)


class HealthSettings(_FrozenModel):
    """Bounds for one on-demand health measurement (``get_system_health``)."""

    measurement_window_seconds: float = Field(default=1.0, ge=0.1, le=10)
    top_contributors: int = Field(default=5, ge=1, le=25)


class InspectionSettings(_FrozenModel):
    """Bounds on the tree context returned by ``inspect_process``."""

    max_ancestors: int = Field(default=16, ge=0, le=64)
    max_descendants: int = Field(default=50, ge=0, le=500)
    max_port_owners: int = Field(default=8, ge=1, le=64)


class IncidentSettings(_FrozenModel):
    """Incident lifecycle, evidence bounds and persistence pacing."""

    recovery_seconds: float = Field(default=30.0, ge=0, le=3600)
    pre_trigger_seconds: float = Field(default=60.0, ge=0, le=1800)
    max_system_samples: int = Field(default=300, ge=1, le=5000)
    max_contributors: int = Field(default=10, ge=0, le=100)
    persist_interval_seconds: float = Field(default=10.0, ge=1, le=600)
    high_severity_after_seconds: float = Field(default=120.0, gt=0, le=86400)
    max_list: int = Field(default=50, ge=1, le=500)
    maintenance_interval_seconds: float = Field(default=3600.0, ge=1, le=86400)
    max_command_line: int = Field(default=512, ge=16, le=8192)


class DiagnosisSettings(_FrozenModel):
    """Bounds and thresholds for ``diagnose_slowdown``. Shares are percent of the machine."""

    default_lookback_minutes: int = Field(default=30, ge=1, le=10_080)
    max_lookback_minutes: int = Field(default=240, ge=1, le=10_080)
    max_incidents: int = Field(default=20, ge=1, le=200)
    max_findings: int = Field(default=10, ge=1, le=50)
    max_hogs: int = Field(default=5, ge=1, le=25)
    max_stale_trees: int = Field(default=5, ge=1, le=25)
    max_hung_processes: int = Field(default=5, ge=1, le=25)
    max_incidents_per_contributor: int = Field(default=5, ge=1, le=50)
    max_evidence_per_finding: int = Field(default=8, ge=1, le=50)
    max_affected_processes: int = Field(default=5, ge=1, le=50)
    hog_cpu_percent: float = Field(default=10.0, gt=0, le=100)
    hog_memory_percent: float = Field(default=10.0, gt=0, le=100)
    stale_process_age_minutes: int = Field(default=30, ge=1, le=10_080)
    max_hung_windows: int = Field(default=32, ge=1, le=256)
    max_window_title: int = Field(default=80, ge=8, le=512)

    @model_validator(mode="after")
    def _maximum_covers_the_default(self) -> Self:
        if self.max_lookback_minutes < self.default_lookback_minutes:
            raise ValueError(
                "max_lookback_minutes must not be smaller than default_lookback_minutes"
            )
        return self


class AgentSettings(_FrozenModel):
    """Background agent behaviour."""

    health_log_interval_seconds: float = Field(default=60.0, ge=1, le=3600)


class LoggingSettings(_FrozenModel):
    """Logging configuration. Files (agent at logon) rotate at file_max_bytes."""

    level: LogLevel = LogLevel.INFO
    file_max_bytes: int = Field(default=5 * 1024 * 1024, ge=64 * 1024, le=512 * 1024 * 1024)
    file_backup_count: int = Field(default=3, ge=0, le=20)

    @field_validator("level", mode="before")
    @classmethod
    def _normalise_case(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value


class Settings(_FrozenModel):
    """Complete, validated configuration for one Windows Medic process."""

    data_dir: Path
    windows_directory: Path = Path(DEFAULT_WINDOWS_DIRECTORY)
    config_file: Path | None = None
    sampling: SamplingSettings = Field(default_factory=SamplingSettings)
    pressure: PressureThresholds = Field(default_factory=PressureThresholds)
    history: HistorySettings = Field(default_factory=HistorySettings)
    classifiers: ClassifierSettings = Field(default_factory=ClassifierSettings)
    protection: ProtectionSettings = Field(default_factory=ProtectionSettings)
    repairs: RepairSettings = Field(default_factory=RepairSettings)
    health: HealthSettings = Field(default_factory=HealthSettings)
    inspection: InspectionSettings = Field(default_factory=InspectionSettings)
    incidents: IncidentSettings = Field(default_factory=IncidentSettings)
    diagnosis: DiagnosisSettings = Field(default_factory=DiagnosisSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    @field_validator("data_dir")
    @classmethod
    def _must_be_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError(f"data_dir must be an absolute path, got {str(value)!r}")
        return value


def default_data_dir(environ: Mapping[str, str]) -> Path:
    """Return ``%LOCALAPPDATA%\\WindowsMedic`` derived from *environ*.

    Falls back to ``%USERPROFILE%\\AppData\\Local`` when ``LOCALAPPDATA`` is absent. When
    neither hint exists the caller must supply ``WINDOWS_MEDIC_DATA_DIR``.
    """
    local_appdata = _non_empty(environ, "LOCALAPPDATA")
    if local_appdata is not None:
        return Path(local_appdata) / DATA_DIR_NAME
    user_profile = _non_empty(environ, "USERPROFILE")
    if user_profile is not None:
        return Path(user_profile) / "AppData" / "Local" / DATA_DIR_NAME
    raise ConfigurationError(
        "Cannot determine the data directory: neither LOCALAPPDATA nor USERPROFILE is set. "
        f"Set {ENV_DATA_DIR} to an absolute directory path."
    )


def load_settings(*, environ: Mapping[str, str], config_path: Path | None = None) -> Settings:
    """Load and validate settings from defaults, the config file and environment overrides.

    Args:
        environ: The process environment (or a test substitute). Only ``LOCALAPPDATA``,
            ``USERPROFILE`` and the ``WINDOWS_MEDIC_*`` keys are consulted.
        config_path: Explicit config file. When given (or when ``WINDOWS_MEDIC_CONFIG_FILE``
            is set) the file must exist. Otherwise ``<data_dir>/config.toml`` is used when
            present and silently skipped when absent.

    Raises:
        ConfigurationError: On unreadable/invalid TOML, unknown keys, or out-of-range values.
    """
    env_data_dir = _non_empty(environ, ENV_DATA_DIR)
    env_config_file = _non_empty(environ, ENV_CONFIG_FILE)

    if config_path is not None:
        resolved_path, required = config_path, True
    elif env_config_file is not None:
        resolved_path, required = Path(env_config_file), True
    else:
        base_dir = Path(env_data_dir) if env_data_dir is not None else default_data_dir(environ)
        resolved_path, required = base_dir / CONFIG_FILE_NAME, False

    if resolved_path.exists():
        data = _read_toml(resolved_path)
        data["config_file"] = resolved_path
    elif required:
        origin = f" (from {ENV_CONFIG_FILE})" if config_path is None else ""
        raise ConfigurationError(f"Configuration file {resolved_path} does not exist{origin}.")
    else:
        data = {"config_file": None}

    if env_data_dir is not None:
        data["data_dir"] = Path(env_data_dir)
    elif "data_dir" not in data:
        data["data_dir"] = default_data_dir(environ)
    if "windows_directory" not in data:
        data["windows_directory"] = _non_empty(environ, "SYSTEMROOT") or DEFAULT_WINDOWS_DIRECTORY

    env_log_level = _non_empty(environ, ENV_LOG_LEVEL)
    if env_log_level is not None:
        section = data.get("logging", {})
        if isinstance(section, dict):
            data["logging"] = {**section, "level": env_log_level}

    source = str(resolved_path) if data["config_file"] is not None else "built-in defaults"
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError(_describe(exc, source)) from exc


def _read_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigurationError(f"Configuration file {path} is not valid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigurationError(f"Configuration file {path} could not be read: {exc}") from exc
    if "config_file" in document:
        raise ConfigurationError(
            f"Configuration file {path} sets 'config_file', which is derived and not configurable."
        )
    return document


def _describe(exc: ValidationError, source: str) -> str:
    lines = [f"Invalid configuration ({source}):"]
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        lines.append(f"  - {location}: {error['msg']}")
    return "\n".join(lines)


def _non_empty(environ: Mapping[str, str], key: str) -> str | None:
    value = environ.get(key, "").strip()
    return value or None
