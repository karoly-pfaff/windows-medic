"""Structured logging: one JSON object per line.

Every record carries an envelope (``ts``, ``level``, ``logger``, ``event``) plus the fields
attached through :func:`windows_medic.application.observability.log_event`, so stable ids
(incident id, process identity, repair id) are queryable rather than buried in prose. Lines
are bounded: a record whose serialised form exceeds the configured limit is replaced by its
envelope plus ``"truncated": true``.
"""

import json
import logging
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TextIO

from windows_medic.application.observability import EVENT_FIELDS_ATTRIBUTE
from windows_medic.infrastructure.config.settings import LogLevel

DEFAULT_MAX_LINE_LENGTH = 8192


class JsonLineFormatter(logging.Formatter):
    """Format records as bounded single-line JSON objects."""

    def __init__(self, *, max_line_length: int = DEFAULT_MAX_LINE_LENGTH) -> None:
        super().__init__()
        self._max_line_length = max_line_length

    def format(self, record: logging.LogRecord) -> str:
        envelope: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        if record.exc_info:
            envelope["exception"] = self.formatException(record.exc_info)

        fields = getattr(record, EVENT_FIELDS_ATTRIBUTE, None)
        payload = {**fields, **envelope} if isinstance(fields, dict) else envelope

        line = _dump(payload)
        if len(line) > self._max_line_length:
            line = _dump({**envelope, "truncated": True})
        return line


class _StructuredStreamHandler(logging.StreamHandler[TextIO]):
    """Marker subclass so :func:`configure_logging` only replaces handlers it installed."""


class _StructuredFileHandler(RotatingFileHandler):
    """Marker subclass for the bounded, rotating JSON-lines file handler."""


def configure_logging(level: LogLevel, stream: TextIO) -> None:
    """Install (or replace) the structured handler on the root logger at *level*."""
    root = logging.getLogger()
    for handler in [h for h in root.handlers if isinstance(h, _StructuredStreamHandler)]:
        root.removeHandler(handler)
        handler.close()

    handler = _StructuredStreamHandler(stream)
    handler.setFormatter(JsonLineFormatter())
    root.addHandler(handler)
    root.setLevel(logging.getLevelNamesMapping()[level.value])


def configure_file_logging(
    level: LogLevel, path: Path, *, max_bytes: int, backup_count: int
) -> None:
    """Add (or replace) a rotating JSON-lines file handler; the log stays bounded."""
    root = logging.getLogger()
    for handler in [h for h in root.handlers if isinstance(h, _StructuredFileHandler)]:
        root.removeHandler(handler)
        handler.close()
    path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = _StructuredFileHandler(
        path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    file_handler.setFormatter(JsonLineFormatter())
    root.addHandler(file_handler)
    root.setLevel(min(root.level, logging.getLevelNamesMapping()[level.value]))


def close_file_logging() -> None:
    """Detach and close the file handler (so the file can be rotated or removed)."""
    root = logging.getLogger()
    for handler in [h for h in root.handlers if isinstance(h, _StructuredFileHandler)]:
        root.removeHandler(handler)
        handler.close()


def _dump(payload: dict[str, object]) -> str:
    return json.dumps(payload, default=str, ensure_ascii=False, separators=(",", ":"))
