"""Centralized protection policy.

Classifies a process into an ordered protection level with explicit reasons. Windows
refusing an operation is not the policy; this is defence in depth and it errs on the side
of protecting: a critical *name* is protected even when its path cannot be read.
"""

from dataclasses import dataclass
from enum import StrEnum

from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.policies.naming import (
    candidate_names,
    lowered,
    names_start_with_marker,
    under_directory,
)

# Processes whose termination destabilises or logs off the session. Lower-case.
DEFAULT_CRITICAL_PROCESS_NAMES: tuple[str, ...] = (
    "system",
    "registry",
    "memory compression",
    "secure system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "fontdrvhost.exe",
)

# Windows components whose termination is disruptive but recoverable; higher risk, not
# forbidden (Explorer and DWM restarts are explicit recipes of their own).
DEFAULT_WINDOWS_COMPONENT_NAMES: tuple[str, ...] = (
    "explorer.exe",
    "dwm.exe",
    "svchost.exe",
    "taskhostw.exe",
    "sihost.exe",
    "ctfmon.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "textinputhost.exe",
    "spoolsv.exe",
    "audiodg.exe",
    "dllhost.exe",
    "wmiprvse.exe",
    "msmpeng.exe",
    "conhost.exe",
)


class ProtectionLevel(StrEnum):
    """Ordered by severity: ``NONE < WINDOWS_COMPONENT < PROTECTED < CRITICAL``.

    ``str`` ordering would be alphabetical, so the comparisons are defined explicitly.
    """

    NONE = "none"
    WINDOWS_COMPONENT = "windows_component"
    PROTECTED = "protected"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    def __lt__(self, other: object) -> bool:
        return self.rank < other.rank if isinstance(other, ProtectionLevel) else NotImplemented

    def __le__(self, other: object) -> bool:
        return self.rank <= other.rank if isinstance(other, ProtectionLevel) else NotImplemented

    def __gt__(self, other: object) -> bool:
        return self.rank > other.rank if isinstance(other, ProtectionLevel) else NotImplemented

    def __ge__(self, other: object) -> bool:
        return self.rank >= other.rank if isinstance(other, ProtectionLevel) else NotImplemented


_RANKS = {
    ProtectionLevel.NONE: 0,
    ProtectionLevel.WINDOWS_COMPONENT: 1,
    ProtectionLevel.PROTECTED: 2,
    ProtectionLevel.CRITICAL: 3,
}


class ProtectionReason(StrEnum):
    CRITICAL_WINDOWS_PROCESS = "critical_windows_process"
    WINDOWS_MEDIC_SELF = "windows_medic_self"
    USER_CONFIGURED = "user_configured"
    WINDOWS_COMPONENT_NAME = "windows_component_name"
    WINDOWS_DIRECTORY = "windows_directory"


_LEVEL_FOR_REASON = {
    ProtectionReason.CRITICAL_WINDOWS_PROCESS: ProtectionLevel.CRITICAL,
    ProtectionReason.WINDOWS_MEDIC_SELF: ProtectionLevel.PROTECTED,
    ProtectionReason.USER_CONFIGURED: ProtectionLevel.PROTECTED,
    ProtectionReason.WINDOWS_COMPONENT_NAME: ProtectionLevel.WINDOWS_COMPONENT,
    ProtectionReason.WINDOWS_DIRECTORY: ProtectionLevel.WINDOWS_COMPONENT,
}


@dataclass(frozen=True, slots=True)
class ProtectionVerdict:
    level: ProtectionLevel
    reasons: tuple[ProtectionReason, ...]


@dataclass(frozen=True, slots=True)
class ProtectionPolicy:
    """Inputs to classification. Built once at the composition root from settings."""

    own_pid: int | None
    windows_medic_markers: tuple[str, ...]
    user_protected_names: tuple[str, ...]
    windows_directory: str
    critical_names: tuple[str, ...] = DEFAULT_CRITICAL_PROCESS_NAMES
    component_names: tuple[str, ...] = DEFAULT_WINDOWS_COMPONENT_NAMES


def classify_protection(
    observation: ProcessObservation, policy: ProtectionPolicy
) -> ProtectionVerdict:
    """Classify one observation. Total and deterministic; never raises on missing fields."""
    names = candidate_names(observation)
    reasons: list[ProtectionReason] = []

    if names & lowered(policy.critical_names):
        reasons.append(ProtectionReason.CRITICAL_WINDOWS_PROCESS)
    if observation.identity.pid == policy.own_pid or names_start_with_marker(
        observation, policy.windows_medic_markers
    ):
        reasons.append(ProtectionReason.WINDOWS_MEDIC_SELF)
    if names & lowered(policy.user_protected_names):
        reasons.append(ProtectionReason.USER_CONFIGURED)
    if names & lowered(policy.component_names):
        reasons.append(ProtectionReason.WINDOWS_COMPONENT_NAME)
    if available(observation.exe_path) and under_directory(
        observation.exe_path, policy.windows_directory
    ):
        reasons.append(ProtectionReason.WINDOWS_DIRECTORY)

    level = max((_LEVEL_FOR_REASON[r] for r in reasons), default=ProtectionLevel.NONE)
    return ProtectionVerdict(level, tuple(reasons))
