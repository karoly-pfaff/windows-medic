"""Component recovery policy: which instance is the session's shell/compositor, what counts as
its replacement, and how each recipe is classified."""

from dataclasses import replace
from datetime import timedelta

import pytest

from tests.builders import BOOT, NOT_SUPPORTED, T0, identity, process, process_snapshot
from windows_medic.domain.models.component import WindowsComponent
from windows_medic.domain.models.repair import RepairAction, RiskLevel
from windows_medic.domain.policies.component_recovery import (
    component_recipe,
    replacement_instance,
    select_component_instance,
    session_of,
)

SNAPSHOT = process_snapshot(
    process(4, name="System"),
    replace(process(100, name="explorer.exe", created=BOOT), session_id=1),
    replace(process(101, name="Explorer.EXE", created=BOOT + timedelta(minutes=5)), session_id=1),
    replace(process(200, name="explorer.exe", created=BOOT), session_id=2),
    replace(process(300, name="dwm.exe", created=BOOT), session_id=1),
    replace(process(4242, name="windows-medic.exe"), session_id=1),
)


class TestSession:
    def test_own_session_comes_from_our_own_observation(self) -> None:
        assert session_of(SNAPSHOT, 4242) == 1

    def test_unknown_when_we_are_not_in_the_snapshot_or_the_session_is_unavailable(
        self,
    ) -> None:
        assert session_of(SNAPSHOT, 9999) is None
        without = process_snapshot(replace(process(4242), session_id=NOT_SUPPORTED))
        assert session_of(without, 4242) is None


class TestSelection:
    def test_the_oldest_instance_in_the_session_is_the_shell(self) -> None:
        chosen = select_component_instance(SNAPSHOT, WindowsComponent.EXPLORER, session=1)

        assert chosen is not None
        assert chosen.identity == identity(100)

    def test_other_sessions_are_never_selected(self) -> None:
        chosen = select_component_instance(SNAPSHOT, WindowsComponent.DWM, session=2)

        assert chosen is None

    def test_name_matching_is_case_insensitive_and_exact(self) -> None:
        snapshot = process_snapshot(
            replace(process(7, name="DWM.EXE"), session_id=3),
            replace(process(8, name="dwm.exe.bak"), session_id=3),
        )

        chosen = select_component_instance(snapshot, WindowsComponent.DWM, session=3)

        assert chosen is not None
        assert chosen.identity.pid == 7


class TestReplacement:
    def test_a_new_instance_in_the_session_created_after_the_plan_is_the_replacement(
        self,
    ) -> None:
        old = identity(100)
        after = process_snapshot(
            replace(
                process(101, name="explorer.exe", created=BOOT + timedelta(minutes=5)), session_id=1
            ),
            replace(
                process(150, name="explorer.exe", created=T0 + timedelta(seconds=2)), session_id=1
            ),
            replace(
                process(250, name="explorer.exe", created=T0 + timedelta(seconds=2)), session_id=2
            ),
        )

        found = replacement_instance(after, WindowsComponent.EXPLORER, session=1, old=old, since=T0)

        assert found is not None
        assert found.identity.pid == 150

    def test_pre_existing_instances_and_the_old_one_are_not_replacements(self) -> None:
        old = identity(100)
        after = process_snapshot(
            replace(process(100, name="explorer.exe", created=BOOT), session_id=1),
            replace(
                process(101, name="explorer.exe", created=BOOT + timedelta(minutes=5)), session_id=1
            ),
        )

        assert (
            replacement_instance(after, WindowsComponent.EXPLORER, session=1, old=old, since=T0)
            is None
        )


class TestRecipes:
    def test_explorer_is_medium_risk_and_unelevated(self) -> None:
        recipe = component_recipe(WindowsComponent.EXPLORER)

        assert recipe.action is RepairAction.WINDOWS_EXPLORER_RESTART
        assert recipe.risk is RiskLevel.MEDIUM
        assert recipe.requires_elevation is False
        assert recipe.may_start is True

    def test_dwm_is_high_risk_elevated_and_never_started_by_us(self) -> None:
        recipe = component_recipe(WindowsComponent.DWM)

        assert recipe.action is RepairAction.WINDOWS_DWM_RESTART
        assert recipe.risk is RiskLevel.HIGH
        assert recipe.requires_elevation is True
        assert recipe.may_start is False

    @pytest.mark.parametrize(
        ("component", "image"),
        [(WindowsComponent.EXPLORER, "explorer.exe"), (WindowsComponent.DWM, "dwm.exe")],
    )
    def test_image_names(self, component: WindowsComponent, image: str) -> None:
        assert component.image_name == image
