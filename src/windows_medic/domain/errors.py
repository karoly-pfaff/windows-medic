"""Explicit error types for expected failures.

Adapters and use cases raise subclasses of :class:`WindowsMedicError` so delivery
mechanisms can report them as deliberate outcomes instead of stack traces.
"""

from windows_medic.domain.models.process import ProcessIdentity


class WindowsMedicError(Exception):
    """Base for every expected, user-reportable failure."""


class ObservationError(WindowsMedicError):
    """A required observation could not be taken at all (as opposed to one missing field)."""


class ProcessNotFoundError(WindowsMedicError):
    """No process with the requested PID exists right now."""

    def __init__(self, pid: int) -> None:
        super().__init__(f"no process with pid {pid} exists")
        self.pid = pid


class StaleIdentityError(WindowsMedicError):
    """The PID exists but belongs to a different process instance than the one requested."""

    def __init__(self, requested: ProcessIdentity, current: ProcessIdentity) -> None:
        super().__init__(
            f"{requested} no longer exists; pid {current.pid} now belongs to a process "
            f"created at {current.create_time.isoformat()}"
        )
        self.requested = requested
        self.current = current


class IncidentStoreError(WindowsMedicError):
    """The incident store could not complete an operation within its bounded retries."""


class RepairAuditError(WindowsMedicError):
    """The repair audit could not be written; a repair is not attempted without it."""


class StartupRegistrationError(WindowsMedicError):
    """The logon startup registration could not be read or changed."""


class WorkspaceError(WindowsMedicError):
    """The data directory or one of its files could not be prepared or written."""
