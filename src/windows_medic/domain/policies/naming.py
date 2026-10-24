"""Case-insensitive, separator-aware matching of process names, paths and command lines.

Windows paths are case-insensitive and may use either separator; a marker matches when it
is a *prefix of a path component*, so ``windows-medic-mcp.exe`` matches ``windows-medic``
but ``my-windows-medic-notes`` does not.
"""

from collections.abc import Iterable

from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessObservation


def normalise(path: str) -> str:
    return path.replace("/", "\\").lower()


def components(value: str) -> list[str]:
    return [part for part in normalise(value).split("\\") if part]


def basename(path: str) -> str:
    parts = components(path)
    return parts[-1] if parts else ""


def names_start_with_marker(observation: ProcessObservation, markers: Iterable[str]) -> bool:
    """True when the executable's file name, or the last component of any command-line
    argument, starts with a marker. Folder names never count: a checkout called
    ``windows-medic`` does not make every process run from it match."""
    lowered_markers = lowered(markers)
    if not lowered_markers:
        return False
    values: list[str] = []
    if available(observation.exe_path):
        values.append(observation.exe_path)
    if available(observation.command_line):
        values.extend(observation.command_line)
    return any(basename(value).startswith(marker) for value in values for marker in lowered_markers)


def lowered(values: Iterable[str]) -> frozenset[str]:
    return frozenset(value.lower() for value in values)


def candidate_names(observation: ProcessObservation) -> frozenset[str]:
    """The observed name and the executable basename, lower-cased, whichever are available."""
    names: set[str] = set()
    if available(observation.name):
        names.add(observation.name.lower())
    if available(observation.exe_path):
        names.add(basename(observation.exe_path))
    return frozenset(names)


def mentions_marker(observation: ProcessObservation, markers: Iterable[str]) -> bool:
    """True when any executable-path or command-line component starts with a marker."""
    lowered_markers = lowered(markers)
    if not lowered_markers:
        return False
    strings: list[str] = []
    if available(observation.exe_path):
        strings.append(observation.exe_path)
    if available(observation.command_line):
        strings.extend(observation.command_line)
    return any(
        component.startswith(marker)
        for value in strings
        for component in components(value)
        for marker in lowered_markers
    )


def under_directory(path: str, directory: str) -> bool:
    """True when *path* lies inside *directory*.

    Separator-aware: ``C:/WindowsApps`` is not inside ``C:/Windows``.
    """
    if not directory:
        return False
    prefix = normalise(directory).rstrip("\\") + "\\"
    return normalise(path).startswith(prefix)
