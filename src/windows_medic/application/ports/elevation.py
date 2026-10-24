"""One-shot elevation as a capability: run exactly one allowlisted recipe as administrator."""

from typing import Protocol

from windows_medic.domain.models.elevation import ElevatedRequest, ElevatedResult


class ElevatedHelper(Protocol):
    """Launches the elevated helper for one request and returns its typed result.

    Implementations never accept anything but an :class:`ElevatedRequest`; there is no
    path for an executable, a command line or a process name to reach the helper.
    """

    def run(self, request: ElevatedRequest) -> ElevatedResult:
        """Run *request* to completion (bounded). Never raises for expected outcomes."""
        ...
