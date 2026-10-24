""":class:`Workspace` over the local filesystem. Small, explicit, and never clever."""

import os
import tempfile
from pathlib import Path

from windows_medic.domain.errors import WorkspaceError


class LocalWorkspace:
    def ensure_directory(self, path: Path) -> None:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WorkspaceError(f"cannot create {path}: {exc}") from exc

    def probe_writable(self, directory: Path) -> str | None:
        if not directory.is_dir():
            return f"{directory} does not exist"
        try:
            handle, name = tempfile.mkstemp(prefix=".write-probe-", dir=directory)
        except OSError as exc:
            return f"{directory} is not writable: {exc}"
        os.close(handle)
        Path(name).unlink(missing_ok=True)
        return None

    def exists(self, path: Path) -> bool:
        return path.exists()

    def size(self, path: Path) -> int | None:
        try:
            return path.stat().st_size
        except OSError:
            return None

    def write_text(self, path: Path, text: str, *, overwrite: bool) -> None:
        if path.exists() and not overwrite:
            raise WorkspaceError(f"{path} already exists (use --force to overwrite)")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise WorkspaceError(f"cannot write {path}: {exc}") from exc

    def children(self, directory: Path) -> tuple[Path, ...]:
        try:
            return tuple(sorted(directory.iterdir()))
        except FileNotFoundError:
            return ()
        except OSError as exc:
            raise WorkspaceError(f"cannot list {directory}: {exc}") from exc

    def remove_file(self, path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise WorkspaceError(f"cannot remove {path}: {exc}") from exc

    def remove_empty_directory(self, path: Path) -> bool:
        if not path.exists():
            return True
        if any(path.iterdir()):
            return False
        try:
            path.rmdir()
        except OSError as exc:
            raise WorkspaceError(f"cannot remove {path}: {exc}") from exc
        return True
