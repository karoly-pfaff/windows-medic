"""Single-instance guard as a capability (a named mutex on Windows)."""

from typing import Protocol


class InstanceLease(Protocol):
    """Held while this process is *the* agent instance; released on exit."""

    def release(self) -> None: ...


class InstanceGuard(Protocol):
    def try_acquire(self) -> InstanceLease | None:
        """The lease, or ``None`` when another process already holds it."""
        ...
