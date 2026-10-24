"""Deterministic, bounded ranking of findings.

Most severe first, then most confident, then in :class:`FindingKind` declaration order
(system-wide pressure before attribution), then by the first affected identity so that
two runs over the same evidence always list findings identically.
"""

from collections.abc import Sequence

from windows_medic.domain.models.finding import Finding, FindingKind

_KIND_ORDER = {kind: index for index, kind in enumerate(FindingKind)}


def rank_findings(findings: Sequence[Finding], *, limit: int) -> tuple[tuple[Finding, ...], bool]:
    """Return the top *limit* findings and whether any were cut off."""
    if limit < 1:
        raise ValueError(f"limit must be at least 1, got {limit}")
    ordered = sorted(findings, key=_key)
    return tuple(ordered[:limit]), len(ordered) > limit


def _key(finding: Finding) -> tuple[int, int, int, int, float, str]:
    first = finding.affected_processes[0].identity if finding.affected_processes else None
    return (
        -finding.severity.rank,
        -finding.confidence.level.rank,
        _KIND_ORDER[finding.kind],
        first.pid if first is not None else -1,
        first.create_time.timestamp() if first is not None else 0.0,
        finding.summary,
    )
