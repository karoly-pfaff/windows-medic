"""Opt-in, disruptive: restart the real Explorer (and, separately opted in, the real DWM).

These restart the developer's own shell session, so they never run by default:

    WINDOWS_MEDIC_DISRUPTIVE_TESTS=1 uv run pytest -m windows_disruptive
    WINDOWS_MEDIC_DISRUPTIVE_TESTS=1 WINDOWS_MEDIC_DWM_TEST=1 uv run pytest -m windows_disruptive

The DWM case additionally needs the UAC prompt to be accepted and flickers the screen.
"""

import io
import os
from pathlib import Path

import pytest

from windows_medic.domain.models.component import WindowsComponent
from windows_medic.domain.models.repair import MemberOutcome, RepairStatus
from windows_medic.domain.policies.component_recovery import (
    select_component_instance,
    session_of,
)
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic.infrastructure.windows.windows_process_reader import WindowsProcessReader
from windows_medic_root.container import compose

pytestmark = [
    pytest.mark.windows_integration,
    pytest.mark.windows_disruptive,
    pytest.mark.skipif(
        os.environ.get("WINDOWS_MEDIC_DISRUPTIVE_TESTS") != "1",
        reason="restarts the real shell; set WINDOWS_MEDIC_DISRUPTIVE_TESTS=1 to opt in",
    ),
]


def _environ(tmp_path: Path, config: str = "") -> dict[str, str]:
    environ = {**os.environ, "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data")}
    if config:
        path = tmp_path / "config.toml"
        path.write_text(config, encoding="utf-8")
        environ["WINDOWS_MEDIC_CONFIG_FILE"] = str(path)
    return environ


def test_explorer_is_restarted_and_a_healthy_replacement_verified(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    container = compose(environ=_environ(tmp_path), log_stream=io.StringIO())
    request.addfinalizer(container.close)
    reader = WindowsProcessReader(SystemClock())
    snapshot = reader.snapshot()
    session = session_of(snapshot, os.getpid())
    assert session is not None
    before = select_component_instance(snapshot, WindowsComponent.EXPLORER, session=session)
    assert before is not None

    record = container.restart_windows_component.execute(WindowsComponent.EXPLORER)

    assert record.status is RepairStatus.SUCCEEDED, record
    assert record.target == before.identity
    assert record.members[0].outcome is MemberOutcome.TERMINATED
    assert record.replacement is not None
    assert record.replacement != before.identity
    assert reader.get(before.identity) is None
    assert reader.get(record.replacement) is not None
    assert container.list_recent_repairs.execute()[0].id == record.id


@pytest.mark.skipif(
    os.environ.get("WINDOWS_MEDIC_DWM_TEST") != "1",
    reason="restarts the real DWM through UAC; set WINDOWS_MEDIC_DWM_TEST=1 to opt in",
)
def test_dwm_is_restarted_through_the_elevated_helper(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    environ = _environ(tmp_path, "[repairs]\nhigh_risk_repairs_enabled = true\n")
    container = compose(environ=environ, log_stream=io.StringIO())
    request.addfinalizer(container.close)
    reader = WindowsProcessReader(SystemClock())

    record = container.restart_windows_component.execute(WindowsComponent.DWM)

    assert record.status is RepairStatus.SUCCEEDED, record
    assert record.target is not None
    assert reader.get(record.target) is None
    assert record.replacement is not None
    assert reader.get(record.replacement) is not None
