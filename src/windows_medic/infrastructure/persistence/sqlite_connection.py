"""SQLite connection policy: WAL, bounded busy wait, foreign keys, migrations, one lock.

One :class:`Database` is shared by every repository in a process. The connection is
opened with ``check_same_thread=False`` because the MCP server runs use cases on worker
threads; all access is serialised through ``lock`` by :class:`SqliteSupervisor`, so no
two statements ever interleave on the connection and cursors are never shared.
"""

import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path

from windows_medic.infrastructure.persistence.migrations import apply_migrations

DEFAULT_BUSY_TIMEOUT_MS = 250


class DatabaseOpenError(Exception):
    """The database could not be opened or migrated (unwritable, corrupt, locked)."""


@dataclass(frozen=True, slots=True)
class Database:
    """A migrated connection plus the lock that serialises access to it."""

    connection: sqlite3.Connection
    lock: threading.RLock = field(default_factory=threading.RLock)

    def close(self) -> None:
        with self.lock:
            self.connection.close()


def open_database(path: Path, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> Database:
    """Open (creating if needed) the database at *path* and migrate it.

    The connection runs in autocommit mode; repositories use explicit ``BEGIN``/``COMMIT``
    for short transactions. WAL lets the agent write while CLI/MCP readers query.

    Raises:
        DatabaseOpenError: When the file cannot be created, read or migrated; no
            connection is left open.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    except (OSError, sqlite3.Error) as exc:
        raise DatabaseOpenError(f"cannot open the database {path}: {exc}") from exc
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        connection.execute("PRAGMA foreign_keys=ON")
        apply_migrations(connection)
    except sqlite3.Error as exc:
        connection.close()
        raise DatabaseOpenError(f"cannot open the database {path}: {exc}") from exc
    return Database(connection)
