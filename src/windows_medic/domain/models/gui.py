"""GUI facts reported by Windows about top-level windows."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HungWindow:
    """A top-level window Windows reports as not responding.

    Windows reports the owning *PID* only; mapping it to an exact process identity is the
    caller's job and the mapping may fail. ``title`` is bounded by the adapter.
    """

    owner_pid: int
    title: str

    def __post_init__(self) -> None:
        if self.owner_pid < 0:
            raise ValueError("owner_pid cannot be negative")
