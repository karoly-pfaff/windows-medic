"""Process termination as a capability. Always by exact identity, never by PID alone."""

from typing import Protocol

from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import TerminationAttempt


class ProcessController(Protocol):
    """Mutates processes. Every operation re-checks the identity it is handed."""

    def terminate(self, identity: ProcessIdentity) -> TerminationAttempt:
        """Ask the OS to terminate exactly *identity*.

        Must verify the create time behind the PID before acting and report
        ``IDENTITY_MISMATCH`` (touching nothing) when the PID now belongs to another
        process. Never raises for expected outcomes; they are returned.
        """
        ...
