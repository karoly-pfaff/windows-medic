"""Repair risk: protection and tree context decide how risky a termination would be."""

from dataclasses import replace

import pytest

from tests.builders import NOT_SUPPORTED, process
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.repair import RepairBlocker, RepairScope, RiskLevel
from windows_medic.domain.policies.protection import (
    ProtectionLevel,
    ProtectionReason,
    ProtectionVerdict,
)
from windows_medic.domain.policies.repair_risk import assess_repair_risk
from windows_medic.domain.policies.risk_markers import RiskMarker

UNPROTECTED = ProtectionVerdict(ProtectionLevel.NONE, ())


def test_plain_user_process_is_low_risk_and_eligible() -> None:
    risk = assess_repair_risk(
        process(10), protection=UNPROTECTED, risk_markers=(), scope=RepairScope.PROCESS
    )

    assert risk.level is RiskLevel.LOW
    assert risk.blockers == ()
    assert risk.requires_elevation is False


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        (
            ProtectionVerdict(
                ProtectionLevel.CRITICAL, (ProtectionReason.CRITICAL_WINDOWS_PROCESS,)
            ),
            RiskLevel.CRITICAL,
        ),
        (
            ProtectionVerdict(ProtectionLevel.PROTECTED, (ProtectionReason.WINDOWS_MEDIC_SELF,)),
            RiskLevel.HIGH,
        ),
        (
            ProtectionVerdict(
                ProtectionLevel.WINDOWS_COMPONENT, (ProtectionReason.WINDOWS_COMPONENT_NAME,)
            ),
            RiskLevel.HIGH,
        ),
    ],
)
def test_any_protection_blocks_the_target_and_raises_risk(
    verdict: ProtectionVerdict, expected: RiskLevel
) -> None:
    risk = assess_repair_risk(
        process(10), protection=verdict, risk_markers=(), scope=RepairScope.PROCESS
    )

    assert risk.level is expected
    assert risk.blockers == (RepairBlocker.TARGET_PROTECTED,)


@pytest.mark.parametrize("marker", [RiskMarker.CLAUDE_ANCESTRY, RiskMarker.TERMINAL_ANCESTRY])
def test_ambiguous_user_intent_makes_the_action_medium_risk(marker: RiskMarker) -> None:
    risk = assess_repair_risk(
        process(10), protection=UNPROTECTED, risk_markers=(marker,), scope=RepairScope.PROCESS
    )

    assert risk.level is RiskLevel.MEDIUM
    assert risk.blockers == ()


def test_tree_scope_with_a_protected_member_is_blocked_and_high_risk() -> None:
    risk = assess_repair_risk(
        process(10),
        protection=UNPROTECTED,
        risk_markers=(RiskMarker.PROTECTED_DESCENDANT,),
        scope=RepairScope.TREE,
    )

    assert risk.level is RiskLevel.HIGH
    assert risk.blockers == (RepairBlocker.TREE_CONTAINS_PROTECTED,)


def test_process_scope_ignores_protected_descendants() -> None:
    risk = assess_repair_risk(
        process(10),
        protection=UNPROTECTED,
        risk_markers=(RiskMarker.PROTECTED_DESCENDANT,),
        scope=RepairScope.PROCESS,
    )

    assert risk.level is RiskLevel.LOW
    assert risk.blockers == ()


def test_blockers_combine_in_declared_order_and_the_worst_risk_wins() -> None:
    risk = assess_repair_risk(
        process(10),
        protection=ProtectionVerdict(
            ProtectionLevel.WINDOWS_COMPONENT, (ProtectionReason.WINDOWS_DIRECTORY,)
        ),
        risk_markers=(RiskMarker.PROTECTED_DESCENDANT, RiskMarker.TERMINAL_ANCESTRY),
        scope=RepairScope.TREE,
    )

    assert risk.level is RiskLevel.HIGH
    assert risk.blockers == (
        RepairBlocker.TARGET_PROTECTED,
        RepairBlocker.TREE_CONTAINS_PROTECTED,
    )


@pytest.mark.parametrize(
    "observation",
    [
        replace(process(10), username=Unavailable(UnavailableReason.ACCESS_DENIED)),
        replace(process(10), session_id=0),
        replace(process(10), session_id=NOT_SUPPORTED),
    ],
)
def test_processes_we_cannot_identify_as_our_own_need_elevation(
    observation: ProcessObservation,
) -> None:
    risk = assess_repair_risk(
        observation, protection=UNPROTECTED, risk_markers=(), scope=RepairScope.PROCESS
    )

    assert risk.requires_elevation is True
    assert risk.level is RiskLevel.MEDIUM
