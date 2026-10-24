"""Ordered schema migrations. Append only; never edit an applied migration."""

import sqlite3

_V1 = """
CREATE TABLE incidents (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    started_at TEXT NOT NULL,
    triggered_at TEXT NOT NULL,
    recovering_since TEXT,
    closed_at TEXT,
    threshold REAL NOT NULL,
    peak REAL NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX incidents_started_at ON incidents (started_at DESC);
CREATE INDEX incidents_ended_at ON incidents (COALESCE(closed_at, started_at));
CREATE TABLE incident_system_samples (
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    cpu_percent REAL,
    cpu_percent_unavailable TEXT,
    memory_percent_used REAL NOT NULL,
    memory_available_bytes INTEGER NOT NULL,
    process_count INTEGER NOT NULL,
    PRIMARY KEY (incident_id, position)
);
CREATE TABLE incident_contributors (
    incident_id TEXT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    create_time TEXT NOT NULL,
    name TEXT,
    name_unavailable TEXT,
    exe_path TEXT,
    exe_path_unavailable TEXT,
    command_line TEXT,
    command_line_unavailable TEXT,
    cpu_percent REAL,
    cpu_percent_unavailable TEXT,
    working_set_bytes INTEGER,
    working_set_bytes_unavailable TEXT,
    private_bytes INTEGER,
    private_bytes_unavailable TEXT,
    PRIMARY KEY (incident_id, position)
);
"""

_V2 = """
CREATE TABLE repairs (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    scope TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    completed_at TEXT,
    target_pid INTEGER,
    target_create_time TEXT,
    port INTEGER,
    risk TEXT,
    requires_elevation INTEGER NOT NULL,
    rejection TEXT,
    verification_passed INTEGER,
    verification_detail TEXT,
    verification_checked_at TEXT
);
CREATE INDEX repairs_requested_at ON repairs (requested_at DESC);
CREATE TABLE repair_members (
    repair_id TEXT NOT NULL REFERENCES repairs (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    create_time TEXT NOT NULL,
    name TEXT,
    name_unavailable TEXT,
    depth INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT,
    PRIMARY KEY (repair_id, position)
);
CREATE TABLE repair_appeared (
    repair_id TEXT NOT NULL REFERENCES repairs (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    create_time TEXT NOT NULL,
    PRIMARY KEY (repair_id, position)
);
"""

_V3 = """
ALTER TABLE repairs ADD COLUMN replacement_pid INTEGER;
ALTER TABLE repairs ADD COLUMN replacement_create_time TEXT;
"""

MIGRATIONS: tuple[str, ...] = (_V1, _V2, _V3)
SCHEMA_VERSION = len(MIGRATIONS)


def apply_migrations(connection: sqlite3.Connection) -> None:
    """Bring the database to :data:`SCHEMA_VERSION`; each step runs in its own transaction."""
    connection.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
    applied = {row[0] for row in connection.execute("SELECT version FROM schema_version")}
    for version, script in enumerate(MIGRATIONS, start=1):
        if version not in applied:
            apply_step(connection, version, script)


def apply_step(connection: sqlite3.Connection, version: int, script: str) -> bool:
    """Apply one migration unless another connection already has; True when applied here.

    Whether it is applied is decided under the write lock: two processes opening a fresh
    database at once (the agent and the MCP server) must not both run the same step.
    """
    connection.execute("BEGIN IMMEDIATE")
    try:
        if connection.execute(
            "SELECT 1 FROM schema_version WHERE version = ?", (version,)
        ).fetchone():
            connection.execute("COMMIT")
            return False
        # executescript() would commit first; run the statements inside our transaction.
        for statement in script.split(";"):
            if statement.strip():
                connection.execute(statement)
        connection.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
        connection.execute("COMMIT")
    except sqlite3.Error:
        connection.execute("ROLLBACK")
        raise
    return True
