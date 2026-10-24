"""Windows shell components with explicit recovery recipes. A closed vocabulary."""

from dataclasses import dataclass
from enum import StrEnum


class WindowsComponent(StrEnum):
    EXPLORER = "explorer"
    DWM = "dwm"

    @property
    def image_name(self) -> str:
        return _IMAGE_NAMES[self]


_IMAGE_NAMES = {WindowsComponent.EXPLORER: "explorer.exe", WindowsComponent.DWM: "dwm.exe"}


@dataclass(frozen=True, slots=True)
class StartAttempt:
    """What happened when a component was asked to start: the new PID, or why not."""

    pid: int | None
    detail: str | None = None
