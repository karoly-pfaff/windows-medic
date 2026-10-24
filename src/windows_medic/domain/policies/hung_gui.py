"""Hung GUI findings (product spec §7.5).

"Hung" is Windows' own verdict about a top-level window, exposed as evidence; it is never
inferred from CPU figures. Windows names owners by PID, so the caller resolves each window
to an exact identity first. Windows whose owner could not be pinned are still reported,
at low confidence, with no process attached and nothing to act on.
"""

from collections.abc import Sequence
from datetime import datetime

from windows_medic.domain.models.evidence import Evidence, EvidenceKind
from windows_medic.domain.models.finding import (
    Confidence,
    ConfidenceAssessment,
    ConfidenceFactor,
    ConfidenceReason,
    Effect,
    Finding,
    FindingKind,
)
from windows_medic.domain.models.gui import HungWindow
from windows_medic.domain.models.incident import Severity
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.tree import DEFAULT_DESCENDANT_LIMIT, ProcessTree
from windows_medic.domain.policies.finding_assembly import (
    FindingLimits,
    affected_from_tree,
    describe,
)
from windows_medic.domain.policies.protection import ProtectionPolicy
from windows_medic.domain.policies.repair_planning import plan_termination
from windows_medic.domain.policies.risk_markers import AncestryPolicy


def hung_gui_findings(
    resolved: Sequence[tuple[HungWindow, ProcessIdentity]],
    unverified: Sequence[HungWindow],
    *,
    tree: ProcessTree,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
    window: tuple[datetime, datetime],
    limits: FindingLimits,
    max_findings: int,
    descendant_limit: int = DEFAULT_DESCENDANT_LIMIT,
) -> tuple[Finding, ...]:
    """One finding per hung process (identity order), then one for unverified windows."""
    by_identity: dict[ProcessIdentity, list[HungWindow]] = {}
    for hung, identity in resolved:
        by_identity.setdefault(identity, []).append(hung)

    findings: list[Finding] = []
    for identity in sorted(by_identity):
        if len(findings) >= max_findings:
            return tuple(findings)
        findings.append(
            _process_finding(
                identity,
                by_identity[identity],
                tree=tree,
                protection=protection,
                ancestry=ancestry,
                window=window,
                limits=limits,
                descendant_limit=descendant_limit,
            )
        )
    if unverified and len(findings) < max_findings:
        findings.append(_unverified_finding(unverified, window=window, limits=limits))
    return tuple(findings)


def _process_finding(
    identity: ProcessIdentity,
    windows: list[HungWindow],
    *,
    tree: ProcessTree,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
    window: tuple[datetime, datetime],
    limits: FindingLimits,
    descendant_limit: int,
) -> Finding:
    evidence = limits.bound(
        [
            Evidence(
                EvidenceKind.HUNG_WINDOW,
                f"window {hung.title!r} is not responding",
                identity=identity,
            )
            for hung in windows
        ]
    )
    count = len(windows)
    return Finding(
        kind=FindingKind.HUNG_GUI,
        severity=Severity.MEDIUM,
        confidence=ConfidenceAssessment(
            Confidence.HIGH,
            (ConfidenceFactor(ConfidenceReason.HUNG_WINDOW_REPORTED, Effect.RAISES),),
        ),
        summary=(
            f"{describe(tree.observation(identity))} is not responding: "
            f"{count} hung window" + ("s" if count > 1 else "")
        ),
        window=window,
        evidence=evidence,
        affected_processes=(
            affected_from_tree(
                identity,
                tree,
                protection=protection,
                ancestry=ancestry,
                descendant_limit=descendant_limit,
            ),
        ),
        candidate_repairs=plan_termination(
            identity,
            tree,
            protection=protection,
            ancestry=ancestry,
            evidence=evidence,
            descendant_limit=descendant_limit,
        ),
    )


def _unverified_finding(
    windows: Sequence[HungWindow], *, window: tuple[datetime, datetime], limits: FindingLimits
) -> Finding:
    count = len(windows)
    return Finding(
        kind=FindingKind.HUNG_GUI,
        severity=Severity.LOW,
        confidence=ConfidenceAssessment(
            Confidence.LOW,
            (
                ConfidenceFactor(ConfidenceReason.HUNG_WINDOW_REPORTED, Effect.RAISES),
                ConfidenceFactor(ConfidenceReason.OWNER_UNVERIFIED, Effect.LOWERS),
            ),
        ),
        summary=f"{count} hung window"
        + ("s" if count > 1 else "")
        + " whose owner could not be verified",
        window=window,
        evidence=limits.bound(
            [
                Evidence(
                    EvidenceKind.HUNG_WINDOW,
                    f"window {hung.title!r} (reported pid {hung.owner_pid}) is not responding",
                )
                for hung in windows
            ]
        ),
        affected_processes=(),
        candidate_repairs=(),
    )
