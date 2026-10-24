"""Development-process classification.

A process is *development tooling* when its executable name is on the configured list or a
path/command-line component starts with a configured marker (``npm``, ``vite``,
``ms-playwright`` ...). The result says exactly what matched so it can be reported as
evidence. A classifier match is a hint about *what* a process is, never proof that it is
unwanted: on its own it justifies no action.
"""

from dataclasses import dataclass

from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.policies.naming import candidate_names, lowered, mentions_marker


@dataclass(frozen=True, slots=True)
class DevelopmentClassifier:
    """Configured hints. Built once at the composition root from settings."""

    process_names: tuple[str, ...]
    command_markers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DevelopmentMatch:
    matched_name: str | None
    matched_markers: tuple[str, ...]


def classify_development(
    observation: ProcessObservation, classifier: DevelopmentClassifier
) -> DevelopmentMatch | None:
    """Report what matched, or ``None`` when nothing known about the process matches."""
    names = sorted(candidate_names(observation) & lowered(classifier.process_names))
    markers = tuple(
        marker
        for marker in sorted(lowered(classifier.command_markers))
        if mentions_marker(observation, (marker,))
    )
    if not names and not markers:
        return None
    return DevelopmentMatch(matched_name=names[0] if names else None, matched_markers=markers)
