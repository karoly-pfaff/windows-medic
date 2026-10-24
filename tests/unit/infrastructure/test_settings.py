"""Typed configuration: safe defaults, config-file layer, narrow env overrides, fail-fast errors."""

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from windows_medic.infrastructure.config.settings import (
    ConfigurationError,
    LogLevel,
    Settings,
    default_data_dir,
    load_settings,
)


@pytest.fixture
def local_appdata(tmp_path: Path) -> Path:
    return tmp_path / "AppData" / "Local"


@pytest.fixture
def environ(local_appdata: Path) -> dict[str, str]:
    return {"LOCALAPPDATA": str(local_appdata)}


def _write_config(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


class TestDefaults:
    def test_data_dir_defaults_under_localappdata(
        self, environ: dict[str, str], local_appdata: Path
    ) -> None:
        settings = load_settings(environ=environ)

        assert settings.data_dir == local_appdata / "WindowsMedic"
        assert settings.config_file is None

    def test_sampling_defaults_match_product_spec(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        assert settings.sampling.system_interval_seconds == 2.0
        assert settings.sampling.process_interval_seconds == 10.0
        assert settings.sampling.pressure_process_interval_seconds == 2.0
        assert settings.sampling.pressure_escalation_max_seconds == 300.0
        assert settings.sampling.pressure_cooldown_seconds == 60.0

    def test_pressure_threshold_defaults_match_product_spec(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        assert settings.pressure.cpu_percent == 90.0
        assert settings.pressure.cpu_duration_seconds == 20.0
        assert settings.pressure.memory_percent == 90.0
        assert settings.pressure.memory_available_floor_mib == 1536
        assert settings.pressure.memory_duration_seconds == 20.0

    def test_history_defaults_match_product_spec(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        assert settings.history.rolling_window_minutes == 30
        assert settings.history.incident_retention_days == 7
        assert settings.history.max_system_samples == 1800
        # The incident engine reads only the last two process snapshots; a full 30-minute
        # history of them cost ~1.5 MiB per snapshot on a 420-process machine in the
        # soak (270 MiB plateau), so the cap is a small multiple of what is used.
        assert settings.history.max_process_snapshots == 12

    def test_incident_defaults_are_bounded_and_documented(self, environ: dict[str, str]) -> None:
        incidents = load_settings(environ=environ).incidents

        assert incidents.recovery_seconds == 30.0
        assert incidents.pre_trigger_seconds == 60.0
        assert incidents.max_system_samples == 300
        assert incidents.max_contributors == 10
        assert incidents.persist_interval_seconds == 10.0
        assert incidents.high_severity_after_seconds == 120.0
        assert incidents.max_list == 50
        assert incidents.maintenance_interval_seconds == 3600.0
        assert incidents.max_command_line == 512

    def test_agent_defaults(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        assert settings.agent.health_log_interval_seconds == 60.0

    def test_agent_bounds_are_enforced(self, environ: dict[str, str], tmp_path: Path) -> None:
        config = _write_config(tmp_path / "bad.toml", "[agent]\nhealth_log_interval_seconds = 0\n")

        with pytest.raises(ConfigurationError, match=r"agent\.health_log_interval_seconds"):
            load_settings(environ=environ, config_path=config)

    def test_safety_defaults_are_conservative(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        assert settings.repairs.high_risk_repairs_enabled is False
        assert settings.repairs.verify_timeout_seconds == 5.0
        assert settings.repairs.verify_interval_seconds == 0.1
        assert settings.repairs.max_tree_members == 200
        assert settings.repairs.audit_retention_days == 30
        assert settings.repairs.max_audit_list == 50
        assert settings.repairs.component_verify_timeout_seconds == 15.0
        assert settings.repairs.component_verify_interval_seconds == 0.25
        assert settings.repairs.explorer_auto_restart_wait_seconds == 5.0
        assert settings.repairs.elevation_timeout_seconds == 120.0
        assert settings.protection.additional_protected_names == ()
        assert "node.exe" in settings.classifiers.development_process_names

    def test_health_measurement_defaults_are_short_and_bounded(
        self, environ: dict[str, str]
    ) -> None:
        settings = load_settings(environ=environ)

        assert settings.health.measurement_window_seconds == 1.0
        assert settings.health.top_contributors == 5

    def test_ancestry_classifier_defaults(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        assert settings.classifiers.claude_markers == ("claude",)
        assert "windowsterminal.exe" in settings.classifiers.terminal_process_names
        assert "pwsh.exe" in settings.classifiers.terminal_process_names

    def test_development_classifier_defaults_cover_common_tooling(
        self, environ: dict[str, str]
    ) -> None:
        classifiers = load_settings(environ=environ).classifiers

        for name in ("node.exe", "esbuild.exe", "python.exe", "headless_shell.exe"):
            assert name in classifiers.development_process_names
        for marker in ("npm", "npx", "vite", "playwright", "ms-playwright", "pytest"):
            assert marker in classifiers.development_command_markers

    def test_diagnosis_defaults_are_bounded_and_documented(self, environ: dict[str, str]) -> None:
        diagnosis = load_settings(environ=environ).diagnosis

        assert diagnosis.default_lookback_minutes == 30
        assert diagnosis.max_lookback_minutes == 240
        assert diagnosis.max_incidents == 20
        assert diagnosis.max_findings == 10
        assert diagnosis.max_hogs == 5
        assert diagnosis.max_stale_trees == 5
        assert diagnosis.max_hung_processes == 5
        assert diagnosis.max_incidents_per_contributor == 5
        assert diagnosis.max_evidence_per_finding == 8
        assert diagnosis.max_affected_processes == 5
        assert diagnosis.hog_cpu_percent == 10.0
        assert diagnosis.hog_memory_percent == 10.0
        assert diagnosis.stale_process_age_minutes == 30
        assert diagnosis.max_hung_windows == 32
        assert diagnosis.max_window_title == 80

    def test_diagnosis_lookback_maximum_must_cover_the_default(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(
            tmp_path / "bad.toml",
            "[diagnosis]\ndefault_lookback_minutes = 60\nmax_lookback_minutes = 30\n",
        )

        with pytest.raises(ConfigurationError, match="max_lookback_minutes"):
            load_settings(environ=environ, config_path=config)

    def test_inspection_limits_default_bounded(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        assert settings.inspection.max_ancestors == 16
        assert settings.inspection.max_descendants == 50
        assert settings.inspection.max_port_owners == 8

    def test_windows_directory_comes_from_systemroot(self, environ: dict[str, str]) -> None:
        environ["SYSTEMROOT"] = "D:\\Win"

        assert load_settings(environ=environ).windows_directory == Path("D:\\Win")

    def test_windows_directory_falls_back_to_the_conventional_location(
        self, environ: dict[str, str]
    ) -> None:
        assert load_settings(environ=environ).windows_directory == Path("C:\\Windows")

    def test_windows_directory_is_configurable(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(tmp_path / "c.toml", 'windows_directory = "E:\\\\Windows"\n')

        assert load_settings(environ=environ, config_path=config).windows_directory == Path(
            "E:\\Windows"
        )

    def test_log_files_are_bounded_by_default(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        assert settings.logging.file_max_bytes == 5 * 1024 * 1024
        assert settings.logging.file_backup_count == 3

    def test_logging_defaults_to_info(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        assert settings.logging.level is LogLevel.INFO

    def test_default_data_dir_falls_back_to_userprofile(self, tmp_path: Path) -> None:
        data_dir = default_data_dir({"USERPROFILE": str(tmp_path)})

        assert data_dir == tmp_path / "AppData" / "Local" / "WindowsMedic"

    def test_default_data_dir_without_any_hint_is_a_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError, match="WINDOWS_MEDIC_DATA_DIR"):
            default_data_dir({})

    def test_settings_are_immutable(self, environ: dict[str, str]) -> None:
        settings = load_settings(environ=environ)

        with pytest.raises(ValidationError):
            settings.repairs.high_risk_repairs_enabled = True  # type: ignore[misc]


class TestConfigFileLayer:
    def test_default_config_file_location_is_under_data_dir(
        self, environ: dict[str, str], local_appdata: Path
    ) -> None:
        config = _write_config(
            local_appdata / "WindowsMedic" / "config.toml",
            '[logging]\nlevel = "DEBUG"\n',
        )

        settings = load_settings(environ=environ)

        assert settings.logging.level is LogLevel.DEBUG
        assert settings.config_file == config

    def test_explicit_config_path_overrides_defaults(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(
            tmp_path / "custom.toml",
            "[sampling]\nsystem_interval_seconds = 5\n\n"
            "[repairs]\nhigh_risk_repairs_enabled = true\n",
        )

        settings = load_settings(environ=environ, config_path=config)

        assert settings.sampling.system_interval_seconds == 5.0
        assert settings.repairs.high_risk_repairs_enabled is True
        assert settings.sampling.process_interval_seconds == 10.0
        assert settings.config_file == config

    def test_list_values_become_tuples(self, environ: dict[str, str], tmp_path: Path) -> None:
        config = _write_config(
            tmp_path / "custom.toml",
            '[protection]\nadditional_protected_names = ["backup-agent.exe"]\n',
        )

        settings = load_settings(environ=environ, config_path=config)

        assert settings.protection.additional_protected_names == ("backup-agent.exe",)

    def test_data_dir_from_config_file(self, environ: dict[str, str], tmp_path: Path) -> None:
        wanted = tmp_path / "elsewhere"
        config = _write_config(tmp_path / "custom.toml", f"data_dir = {str(wanted)!r}\n")

        settings = load_settings(environ=environ, config_path=config)

        assert settings.data_dir == wanted

    def test_explicit_missing_config_file_fails_fast(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        missing = tmp_path / "nope.toml"

        with pytest.raises(ConfigurationError, match=r"nope\.toml"):
            load_settings(environ=environ, config_path=missing)

    def test_invalid_toml_reports_path_and_parse_error(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(tmp_path / "broken.toml", "[sampling\n")

        with pytest.raises(ConfigurationError, match=r"broken\.toml") as excinfo:
            load_settings(environ=environ, config_path=config)

        assert "TOML" in str(excinfo.value)

    def test_unknown_key_is_rejected_with_its_dotted_path(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(tmp_path / "typo.toml", "[sampling]\nsytem_interval_seconds = 1\n")

        with pytest.raises(ConfigurationError, match=r"sampling\.sytem_interval_seconds"):
            load_settings(environ=environ, config_path=config)

    def test_out_of_range_value_is_rejected_with_its_dotted_path(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(tmp_path / "bad.toml", "[sampling]\nsystem_interval_seconds = 0\n")

        with pytest.raises(ConfigurationError, match=r"sampling\.system_interval_seconds"):
            load_settings(environ=environ, config_path=config)

    def test_escalated_interval_may_not_exceed_normal_interval(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(
            tmp_path / "bad.toml",
            "[sampling]\nprocess_interval_seconds = 5\npressure_process_interval_seconds = 6\n",
        )

        with pytest.raises(ConfigurationError, match="pressure_process_interval_seconds"):
            load_settings(environ=environ, config_path=config)

    def test_health_bounds_are_enforced(self, environ: dict[str, str], tmp_path: Path) -> None:
        config = _write_config(tmp_path / "bad.toml", "[health]\ntop_contributors = 500\n")

        with pytest.raises(ConfigurationError, match=r"health\.top_contributors"):
            load_settings(environ=environ, config_path=config)

    def test_relative_data_dir_is_rejected(self, environ: dict[str, str], tmp_path: Path) -> None:
        config = _write_config(tmp_path / "bad.toml", 'data_dir = "relative/dir"\n')

        with pytest.raises(ConfigurationError, match="data_dir"):
            load_settings(environ=environ, config_path=config)

    def test_non_table_section_is_rejected(self, environ: dict[str, str], tmp_path: Path) -> None:
        config = _write_config(tmp_path / "bad.toml", "sampling = 3\n")

        with pytest.raises(ConfigurationError, match="sampling"):
            load_settings(environ=environ, config_path=config)

    def test_derived_config_file_key_is_rejected(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(tmp_path / "bad.toml", 'config_file = "elsewhere.toml"\n')

        with pytest.raises(ConfigurationError, match="config_file"):
            load_settings(environ=environ, config_path=config)

    def test_unreadable_config_path_reports_read_failure(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        directory = tmp_path / "config.toml"
        directory.mkdir()

        with pytest.raises(ConfigurationError, match="could not be read"):
            load_settings(environ=environ, config_path=directory)


class TestEnvironmentLayer:
    def test_env_data_dir_wins_over_config_file(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(
            tmp_path / "custom.toml", f"data_dir = {str(tmp_path / 'from-file')!r}\n"
        )
        environ["WINDOWS_MEDIC_DATA_DIR"] = str(tmp_path / "from-env")

        settings = load_settings(environ=environ, config_path=config)

        assert settings.data_dir == tmp_path / "from-env"

    def test_env_log_level_wins_over_config_file_and_is_case_insensitive(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(tmp_path / "custom.toml", '[logging]\nlevel = "ERROR"\n')
        environ["WINDOWS_MEDIC_LOG_LEVEL"] = "warning"

        settings = load_settings(environ=environ, config_path=config)

        assert settings.logging.level is LogLevel.WARNING

    def test_env_config_file_selects_the_config_file(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(tmp_path / "env.toml", '[logging]\nlevel = "DEBUG"\n')
        environ["WINDOWS_MEDIC_CONFIG_FILE"] = str(config)

        settings = load_settings(environ=environ)

        assert settings.logging.level is LogLevel.DEBUG
        assert settings.config_file == config

    def test_env_config_file_pointing_nowhere_fails_fast(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        environ["WINDOWS_MEDIC_CONFIG_FILE"] = str(tmp_path / "missing.toml")

        with pytest.raises(ConfigurationError, match="WINDOWS_MEDIC_CONFIG_FILE"):
            load_settings(environ=environ)

    def test_invalid_env_log_level_is_rejected(self, environ: dict[str, str]) -> None:
        environ["WINDOWS_MEDIC_LOG_LEVEL"] = "VERBOSE"

        with pytest.raises(ConfigurationError, match=r"logging\.level"):
            load_settings(environ=environ)

    def test_env_log_level_does_not_mask_a_malformed_logging_section(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        config = _write_config(tmp_path / "bad.toml", 'logging = "loud"\n')
        environ["WINDOWS_MEDIC_LOG_LEVEL"] = "INFO"

        with pytest.raises(ConfigurationError, match="logging"):
            load_settings(environ=environ, config_path=config)

    def test_env_data_dir_is_used_to_locate_the_default_config_file(
        self, environ: dict[str, str], tmp_path: Path
    ) -> None:
        data_dir = tmp_path / "custom-data"
        _write_config(data_dir / "config.toml", '[logging]\nlevel = "CRITICAL"\n')
        environ["WINDOWS_MEDIC_DATA_DIR"] = str(data_dir)

        settings = load_settings(environ=environ)

        assert settings.logging.level is LogLevel.CRITICAL
        assert settings.data_dir == data_dir


class TestValidationProperties:
    @given(interval=st.floats(min_value=0.0, max_value=60.0, exclude_min=True))
    def test_any_positive_bounded_system_interval_is_accepted(self, interval: float) -> None:
        settings = Settings.model_validate(
            {"data_dir": "C:\\data", "sampling": {"system_interval_seconds": interval}}
        )

        assert settings.sampling.system_interval_seconds == interval

    @given(interval=st.floats(max_value=0.0, allow_nan=False))
    def test_any_non_positive_system_interval_is_rejected(self, interval: float) -> None:
        with pytest.raises(ValidationError):
            Settings.model_validate(
                {"data_dir": "C:\\data", "sampling": {"system_interval_seconds": interval}}
            )

    @given(minutes=st.integers(max_value=0))
    def test_any_non_positive_rolling_window_is_rejected(self, minutes: int) -> None:
        with pytest.raises(ValidationError):
            Settings.model_validate(
                {"data_dir": "C:\\data", "history": {"rolling_window_minutes": minutes}}
            )
