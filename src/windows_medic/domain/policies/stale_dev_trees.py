"""Suspected stale/orphaned development trees (product spec §7.4).

A tree root is a candidate only with *validated parent evidence*: the kernel-reported
parent PID belongs to no process, or to a process created after the child (a reused PID).
An unknown parent is not evidence. The root must also match the development classifier and
must not be protected. Age and further development tooling in the tree raise confidence;
a protected member lowers it. A name match alone never produces a finding.
"""

from datetime import datetime, timedelta

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
from windows_medic.domain.models.incident import Severity
from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.tree import (
    DEFAULT_DESCENDANT_LIMIT,
    ProcessTree,
    UnresolvedParent,
    UnresolvedParentReason,
)
from windows_medic.domain.policies.finding_assembly import (
    FindingLimits,
    affected_from_tree,
    describe,
    mebibytes,
    minutes,
)
from windows_medic.domain.policies.process_classification import (
    DevelopmentClassifier,
    DevelopmentMatch,
    classify_development,
)
from windows_medic.domain.policies.protection import (
    ProtectionLevel,
    ProtectionPolicy,
    classify_protection,
)
from windows_medic.domain.policies.repair_planning import plan_termination
from windows_medic.domain.policies.resource_hogs import HogThresholds
from windows_medic.domain.policies.risk_markers import AncestryPolicy, RiskMarker

_VALIDATED = {
    UnresolvedParentReason.PARENT_GONE: ConfidenceReason.PARENT_GONE,
    UnresolvedParentReason.PARENT_PID_REUSED: ConfidenceReason.PARENT_PID_REUSED,
}
_PARENT_TEXT = {
    UnresolvedParentReason.PARENT_GONE: "parent gone",
    UnresolvedParentReason.PARENT_PID_REUSED: "parent pid reused",
}


def stale_dev_tree_findings(
    tree: ProcessTree,
    *,
    classifier: DevelopmentClassifier,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
    now: datetime,
    stale_after: timedelta,
    thresholds: HogThresholds,
    memory_total_bytes: int,
    window: tuple[datetime, datetime],
    limits: FindingLimits,
    max_findings: int,
    descendant_limit: int = DEFAULT_DESCENDANT_LIMIT,
) -> tuple[Finding, ...]:
    """One finding per qualifying tree root, in identity order, at most *max_findings*."""
    if memory_total_bytes <= 0:
        raise ValueError("memory_total_bytes must be positive")
    findings: list[Finding] = []
    for root in tree.roots():
        if len(findings) >= max_findings:
            break
        link = tree.parent_of(root)
        if not isinstance(link, UnresolvedParent) or link.reason not in _VALIDATED:
            continue
        observation = tree.observation(root)
        match = classify_development(observation, classifier)
        if (
            match is None
            or classify_protection(observation, protection).level > ProtectionLevel.NONE
        ):
            continue
        findings.append(
            _finding(
                root,
                link,
                match,
                tree,
                protection=protection,
                ancestry=ancestry,
                classifier=classifier,
                now=now,
                stale_after=stale_after,
                thresholds=thresholds,
                memory_total_bytes=memory_total_bytes,
                window=window,
                limits=limits,
                descendant_limit=descendant_limit,
            )
        )
    return tuple(findings)


def _finding(
    root: ProcessIdentity,
    link: UnresolvedParent,
    match: DevelopmentMatch,
    tree: ProcessTree,
    *,
    protection: ProtectionPolicy,
    ancestry: AncestryPolicy,
    classifier: DevelopmentClassifier,
    now: datetime,
    stale_after: timedelta,
    thresholds: HogThresholds,
    memory_total_bytes: int,
    window: tuple[datetime, datetime],
    limits: FindingLimits,
    descendant_limit: int,
) -> Finding:
    observation = tree.observation(root)
    descendants = tree.descendants_of(root, limit=descendant_limit)
    members = [observation] + [tree.observation(d.identity) for d in descendants]
    dev_members = [m for m in members[1:] if classify_development(m, classifier) is not None]
    affected_root = affected_from_tree(
        root, tree, protection=protection, ancestry=ancestry, descendant_limit=descendant_limit
    )
    protected_member = RiskMarker.PROTECTED_DESCENDANT in affected_root.risk_markers
    age = now - root.create_time
    aged = age >= stale_after
    working_set = sum(m.working_set_bytes for m in members if available(m.working_set_bytes))

    factors = [
        ConfidenceFactor(_VALIDATED[link.reason], Effect.RAISES),
        ConfidenceFactor(ConfidenceReason.DEVELOPMENT_CLASSIFIER, Effect.RAISES),
        ConfidenceFactor(
            ConfidenceReason.AGE_EXCEEDS_THRESHOLD if aged else ConfidenceReason.RECENTLY_STARTED,
            Effect.RAISES if aged else Effect.LOWERS,
        ),
    ]
    if dev_members:
        factors.append(
            ConfidenceFactor(ConfidenceReason.MULTIPLE_DEVELOPMENT_MEMBERS, Effect.RAISES)
        )
    if protected_member:
        factors.append(ConfidenceFactor(ConfidenceReason.PROTECTED_MEMBER, Effect.LOWERS))

    if protected_member or not aged:
        level = Confidence.LOW
    elif dev_members:
        level = Confidence.HIGH
    else:
        level = Confidence.MEDIUM

    evidence = [
        Evidence(EvidenceKind.UNRESOLVED_PARENT, _parent_detail(link), identity=root),
        Evidence(EvidenceKind.DEVELOPMENT_CLASSIFIER, _classifier_detail(match), identity=root),
        Evidence(
            EvidenceKind.PROCESS_AGE,
            f"running for {minutes(age)} (stale after {minutes(stale_after)})",
            value=age.total_seconds() / 60,
            identity=root,
        ),
        Evidence(
            EvidenceKind.TREE_MEMBERS,
            f"{_count(len(descendants), 'descendant')}, "
            f"{_count(len(dev_members), 'further development tool')}, "
            f"{mebibytes(working_set)} working set",
            value=float(len(descendants)),
            identity=root,
        ),
    ]
    if protected_member:
        evidence.append(
            Evidence(EvidenceKind.RISK_MARKER, "tree contains a protected process", identity=root)
        )
    bounded = limits.bound(evidence)

    affected = [affected_root] + [
        affected_from_tree(
            m.identity,
            tree,
            protection=protection,
            ancestry=ancestry,
            descendant_limit=descendant_limit,
        )
        for m in dev_members[: limits.max_affected_processes - 1]
    ]
    candidates = (
        plan_termination(
            root,
            tree,
            protection=protection,
            ancestry=ancestry,
            evidence=bounded,
            descendant_limit=descendant_limit,
        )
        if level >= Confidence.MEDIUM
        else ()
    )
    share = working_set / memory_total_bytes * 100.0
    return Finding(
        kind=FindingKind.SUSPECTED_STALE_DEV_TREE,
        severity=Severity.MEDIUM if share >= thresholds.memory_percent else Severity.LOW,
        confidence=ConfidenceAssessment(level, tuple(factors)),
        summary=_summary(observation, len(descendants), link, age),
        window=window,
        evidence=bounded,
        affected_processes=tuple(affected[: limits.max_affected_processes]),
        candidate_repairs=candidates,
    )


def _parent_detail(link: UnresolvedParent) -> str:
    if link.reason is UnresolvedParentReason.PARENT_GONE:
        return f"parent pid {link.parent_pid} no longer exists"
    return f"parent pid {link.parent_pid} now belongs to a newer process"


def _classifier_detail(match: DevelopmentMatch) -> str:
    parts: list[str] = []
    if match.matched_name is not None:
        parts.append(f"name {match.matched_name}")
    if match.matched_markers:
        parts.append(f"markers {', '.join(match.matched_markers)}")
    return "matches development classifier: " + "; ".join(parts)


def _summary(
    observation: ProcessObservation, descendants: int, link: UnresolvedParent, age: timedelta
) -> str:
    subject = describe(observation)
    if descendants:
        subject += f" and {_count(descendants, 'descendant')}"
    return (
        f"{subject}: {_PARENT_TEXT[link.reason]}, development tooling, running for {minutes(age)}"
    )


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" + ("" if number == 1 else "s")
