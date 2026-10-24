"""Opening the database: failures are typed and leave nothing open behind them."""

from pathlib import Path

import pytest

from windows_medic.infrastructure.persistence.sqlite_connection import (
    DatabaseOpenError,
    open_database,
)


def test_a_file_that_is_not_a_database_is_a_typed_error_and_is_not_held_open(
    tmp_path: Path,
) -> None:
    path = tmp_path / "incidents.sqlite3"
    path.write_bytes(b"this is not an SQLite database, just some bytes" * 100)

    with pytest.raises(DatabaseOpenError, match=r"incidents\.sqlite3"):
        open_database(path)

    # Windows refuses to delete a file that still has an open handle.
    path.unlink()


def test_a_directory_that_cannot_be_created_is_a_typed_error(tmp_path: Path) -> None:
    blocker = tmp_path / "data"
    blocker.write_text("a file where the data directory should be")

    with pytest.raises(DatabaseOpenError, match="data"):
        open_database(blocker / "incidents.sqlite3")
