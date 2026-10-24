"""Ordered migrations: each step is atomic and recorded exactly once."""

import sqlite3
from pathlib import Path

import pytest

from windows_medic.infrastructure.persistence import migrations


def test_a_failing_migration_is_rolled_back_and_not_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken = (
        *migrations.MIGRATIONS,
        "CREATE TABLE extra (id INTEGER PRIMARY KEY); INSERT INTO missing VALUES (1)",
    )
    monkeypatch.setattr(migrations, "MIGRATIONS", broken)
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        with pytest.raises(sqlite3.OperationalError, match="missing"):
            migrations.apply_migrations(connection)

        versions = [row[0] for row in connection.execute("SELECT version FROM schema_version")]
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        in_transaction = connection.in_transaction
    finally:
        connection.close()

    assert versions == list(range(1, migrations.SCHEMA_VERSION + 1))
    assert "extra" not in tables
    assert not in_transaction


def test_a_step_another_process_applied_meanwhile_is_skipped_under_the_lock(
    tmp_path: Path,
) -> None:
    # Both connections saw a fresh database; the first one won the race.
    path = tmp_path / "incidents.sqlite3"
    winner = sqlite3.connect(path, isolation_level=None)
    loser = sqlite3.connect(path, isolation_level=None)
    try:
        migrations.apply_migrations(winner)

        applied = [
            migrations.apply_step(loser, version, script)
            for version, script in enumerate(migrations.MIGRATIONS, start=1)
        ]
        versions = [row[0] for row in loser.execute("SELECT version FROM schema_version")]
        in_transaction = loser.in_transaction
    finally:
        winner.close()
        loser.close()

    assert applied == [False] * migrations.SCHEMA_VERSION  # no "table already exists"
    assert versions == list(range(1, migrations.SCHEMA_VERSION + 1))
    assert not in_transaction
