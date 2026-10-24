"""Findings are ranked deterministically: severity, confidence, kind, then identity."""

from datetime import timedelta

import pytest

from tests.builders import BOOT, T0, identity
from windows_medic.domain.models.finding import (
    AffectedProcess,
    Confidence,
    ConfidenceAssessment,
    Finding,
    FindingKind,
)
from windows_medic.domain.models.incident import Severity
from windows_medic.domain.policies.finding_ranking import rank_findings
from windows_medic.domain.policies.protection import ProtectionLevel

WINDOW = (T0 - timedelta(minutes=30), T0)


def finding(
    kind: FindingKind,
    severity: Severity,
    confidence: Confidence,
    *pids: int,
    summary: str = "",
) -> Finding:
    return Finding(
        kind=kind,
        severity=severity,
        confidence=ConfidenceAssessment(confidence, ()),
        summary=summary or f"{kind.value} {severity.value} {confidence.value} {pids}",
        window=WINDOW,
        evidence=(),
        affected_processes=tuple(
            AffectedProcess(identity(pid), "p.exe", "C:\\p.exe", True, ProtectionLevel.NONE, ())
            for pid in pids
        ),
        candidate_repairs=(),
    )


def test_ranking_is_severity_then_confidence_then_kind_then_identity() -> None:
    findings = (
        finding(FindingKind.SUSPECTED_STALE_DEV_TREE, Severity.LOW, Confidence.HIGH, 30),
        finding(FindingKind.RESOURCE_HOG, Severity.MEDIUM, Confidence.LOW, 20),
        finding(FindingKind.RESOURCE_HOG, Severity.HIGH, Confidence.MEDIUM, 12),
        finding(FindingKind.RESOURCE_HOG, Severity.HIGH, Confidence.MEDIUM, 11),
        finding(FindingKind.CPU_PRESSURE, Severity.HIGH, Confidence.MEDIUM),
        finding(FindingKind.MEMORY_PRESSURE, Severity.HIGH, Confidence.HIGH),
    )

    ranked, truncated = rank_findings(findings, limit=10)

    assert [f.summary for f in ranked] == [
        findings[5].summary,
        findings[4].summary,
        findings[3].summary,
        findings[2].summary,
        findings[1].summary,
        findings[0].summary,
    ]
    assert truncated is False


def test_ranking_is_bounded_and_reports_truncation() -> None:
    findings = tuple(
        finding(FindingKind.RESOURCE_HOG, Severity.MEDIUM, Confidence.MEDIUM, pid)
        for pid in (5, 3, 4)
    )

    ranked, truncated = rank_findings(findings, limit=2)

    assert [f.affected_processes[0].identity.pid for f in ranked] == [3, 4]
    assert truncated is True


def test_same_pid_different_create_time_orders_older_first() -> None:
    older = finding(FindingKind.RESOURCE_HOG, Severity.MEDIUM, Confidence.MEDIUM, 7)
    newer = Finding(
        kind=older.kind,
        severity=older.severity,
        confidence=older.confidence,
        summary="newer",
        window=WINDOW,
        evidence=(),
        affected_processes=(
            AffectedProcess(
                identity(7, BOOT + timedelta(hours=1)),
                "p.exe",
                "C:\\p.exe",
                True,
                ProtectionLevel.NONE,
                (),
            ),
        ),
        candidate_repairs=(),
    )

    ranked, _ = rank_findings((newer, older), limit=5)

    assert [f.summary for f in ranked] == [older.summary, "newer"]


def test_ranking_rejects_a_non_positive_limit() -> None:
    with pytest.raises(ValueError, match="limit"):
        rank_findings((), limit=0)
