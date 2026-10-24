"""The user's data directory as a capability: small, explicit file operations."""

from pathlib import Path
from typing import Protocol


class Workspace(Protocol):
    """Filesystem access limited to what the operational commands need."""

    def ensure_directory(self, path: Path) -> None:
        """Create *path* (and parents). Raises WorkspaceError."""
        ...

    def probe_writable(self, directory: Path) -> str | None:
        """``None`` when a file can be created in *directory*, else why not."""
        ...

    def exists(self, path: Path) -> bool: ...

    def size(self, path: Path) -> int | None:
        """File size in bytes, ``None`` when absent."""
        ...

    def write_text(self, path: Path, text: str, *, overwrite: bool) -> None:
        """Write *text*; refuses an existing file unless *overwrite*. Raises WorkspaceError."""
        ...

    def children(self, directory: Path) -> tuple[Path, ...]:
        """The entries directly inside *directory*; empty when it does not exist."""
        ...

    def remove_file(self, path: Path) -> None:
        """Delete one file; absent is fine. Raises WorkspaceError."""
        ...

    def remove_empty_directory(self, path: Path) -> bool:
        """Delete *path* if it is an empty directory; False (and kept) when it is not
        empty, True when it is gone. Never deletes contents. Raises WorkspaceError."""
        ...
