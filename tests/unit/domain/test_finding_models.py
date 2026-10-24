"""Finding, evidence and repair-candidate models: closed vocabularies with explicit order."""

import pytest

from tests.builders import T0, identity
from windows_medic.domain.models.evidence import Evidence, EvidenceKind
from windows_medic.domain.models.finding import (
    Confidence,
    ConfidenceAssessment,
    ConfidenceFactor,
    ConfidenceReason,
    Effect,
    FindingKind,
)
from windows_medic.domain.models.gui import HungWindow
from windows_medic.domain.models.incident import Severity
from windows_medic.domain.models.repair import (
    RepairAction,
    RepairCandidate,
    RepairScope,
    RiskLevel,
)
from windows_medic.domain.policies.finding_assembly import FindingLimits


def test_confidence_is_ordered_low_to_high() -> None:
    assert Confidence.LOW < Confidence.MEDIUM < Confidence.HIGH
    assert Confidence.HIGH >= Confidence.HIGH
    assert max(Confidence.LOW, Confidence.HIGH) is Confidence.HIGH
    assert Confidence.LOW <= Confidence.LOW
    assert Confidence.LOW.__lt__("high") is NotImplemented


def test_severity_is_ordered_low_to_high() -> None:
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH > Severity.LOW
    assert Severity.MEDIUM.__le__(3) is NotImplemented


def test_risk_level_is_ordered_low_to_critical() -> None:
    assert RiskLevel.LOW < RiskLevel.MEDIUM < RiskLevel.HIGH < RiskLevel.CRITICAL
    assert RiskLevel.CRITICAL >= RiskLevel.HIGH
    assert RiskLevel.MEDIUM <= RiskLevel.MEDIUM
    assert RiskLevel.LOW.__gt__(None) is NotImplemented
    assert RiskLevel.LOW.__ge__(None) is NotImplemented


def test_repair_actions_use_the_recipe_ids_from_the_architecture() -> None:
    assert RepairAction.PROCESS_TERMINATE.value == "process.terminate"
    assert RepairAction.PROCESS_TERMINATE_TREE.value == "process.terminate_tree"


def test_repair_candidate_requires_evidence_and_a_target() -> None:
    with pytest.raises(ValueError, match="evidence"):
        RepairCandidate(
            action=RepairAction.PROCESS_TERMINATE,
            target=identity(10),
            scope=RepairScope.PROCESS,
            risk=RiskLevel.LOW,
            requires_elevation=False,
            blockers=(),
            evidence=(),
        )


def test_tree_scope_uses_the_tree_recipe() -> None:
    candidate = RepairCandidate(
        action=RepairAction.PROCESS_TERMINATE_TREE,
        target=identity(10),
        scope=RepairScope.TREE,
        risk=RiskLevel.LOW,
        requires_elevation=False,
        blockers=(),
        evidence=(Evidence(EvidenceKind.PROCESS_AGE, "age 45 min", value=45.0),),
    )

    assert candidate.eligible is True
    assert candidate.evidence[0].window is None
    assert candidate.evidence[0].identity is None


def test_confidence_assessment_lists_its_factors_in_order() -> None:
    assessment = ConfidenceAssessment(
        Confidence.MEDIUM,
        (
            ConfidenceFactor(ConfidenceReason.SUSTAINED_INCIDENT, Effect.RAISES),
            ConfidenceFactor(ConfidenceReason.SINGLE_SAMPLE_ONLY, Effect.LOWERS),
        ),
    )

    assert assessment.raises == (ConfidenceReason.SUSTAINED_INCIDENT,)
    assert assessment.lowers == (ConfidenceReason.SINGLE_SAMPLE_ONLY,)
    assert FindingKind.RESOURCE_HOG.value == "resource_hog"
    assert T0.tzinfo is not None


def test_hung_window_owner_pid_cannot_be_negative() -> None:
    with pytest.raises(ValueError, match="owner_pid"):
        HungWindow(-1, "x")


@pytest.mark.parametrize(("max_evidence", "max_affected"), [(0, 1), (1, 0)])
def test_finding_limits_are_validated(max_evidence: int, max_affected: int) -> None:
    with pytest.raises(ValueError, match="must be at least 1"):
        FindingLimits(max_evidence=max_evidence, max_affected_processes=max_affected)
