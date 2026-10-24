"""The contract between the unelevated process and the one-shot elevated helper.

The helper accepts exactly one allowlisted recipe with typed arguments and returns a typed
result. There is no way to pass an executable, a command line or a process name through
it: the only thing it can do is terminate one exact identity that it has itself verified
to be the component the recipe names.
"""

from dataclasses import dataclass
from enum import StrEnum

from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import TerminationAttempt


class ElevatedRecipe(StrEnum):
    """Everything the elevated helper is allowed to do."""

    WINDOWS_DWM_TERMINATE = "windows.dwm.terminate"


@dataclass(frozen=True, slots=True)
class ElevatedRequest:
    recipe: ElevatedRecipe
    target: ProcessIdentity
    session: int

    def __post_init__(self) -> None:
        if self.session < 0:
            raise ValueError("session cannot be negative")


class ElevatedOutcome(StrEnum):
    COMPLETED = "completed"
    REJECTED = "rejected"
    DECLINED = "declined"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class ElevatedRejection(StrEnum):
    """Why the helper refused. Decided by the helper, never by the caller."""

    UNKNOWN_RECIPE = "unknown_recipe"
    MALFORMED_ARGUMENTS = "malformed_arguments"
    TARGET_NOT_FOUND = "target_not_found"
    STALE_IDENTITY = "stale_identity"
    NOT_THE_COMPONENT = "not_the_component"
    SESSION_MISMATCH = "session_mismatch"


@dataclass(frozen=True, slots=True)
class ElevatedResult:
    outcome: ElevatedOutcome
    termination: TerminationAttempt | None = None
    rejection: ElevatedRejection | None = None
    detail: str | None = None
