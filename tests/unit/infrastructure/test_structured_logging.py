"""Structured logging: one bounded JSON object per line with event name and stable ids."""

import io
import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from windows_medic.application.observability import log_event
from windows_medic.infrastructure.config.settings import LogLevel
from windows_medic.infrastructure.observability.structured_logging import (
    JsonLineFormatter,
    configure_logging,
)


@pytest.fixture
def root_logger_state() -> Iterator[None]:
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


@pytest.fixture
def stream() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def logger(stream: io.StringIO) -> Iterator[logging.Logger]:
    test_logger = logging.getLogger("windows_medic.test.structured")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonLineFormatter())
    test_logger.addHandler(handler)
    test_logger.setLevel(logging.DEBUG)
    test_logger.propagate = False
    yield test_logger
    test_logger.removeHandler(handler)


def _fail_collector() -> None:
    raise ValueError("boom")


def _single_line(stream: io.StringIO) -> dict[str, object]:
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1, lines
    parsed = json.loads(lines[0])
    assert isinstance(parsed, dict)
    return parsed


class TestJsonLineFormatter:
    def test_emits_one_json_object_with_envelope_keys(
        self, logger: logging.Logger, stream: io.StringIO
    ) -> None:
        logger.info("agent.started")

        record = _single_line(stream)

        assert record["event"] == "agent.started"
        assert record["level"] == "INFO"
        assert record["logger"] == "windows_medic.test.structured"
        assert isinstance(record["ts"], str)

    def test_timestamp_is_utc_iso8601(self, logger: logging.Logger, stream: io.StringIO) -> None:
        logger.info("tick")

        timestamp = _single_line(stream)["ts"]
        assert isinstance(timestamp, str)

        parsed = datetime.fromisoformat(timestamp)
        assert parsed.tzinfo == UTC

    def test_event_fields_become_top_level_keys(
        self, logger: logging.Logger, stream: io.StringIO
    ) -> None:
        log_event(logger, "incident.opened", incident_id="inc-1", pid=42)

        record = _single_line(stream)

        assert record["incident_id"] == "inc-1"
        assert record["pid"] == 42

    def test_event_level_is_honoured(self, logger: logging.Logger, stream: io.StringIO) -> None:
        log_event(logger, "repair.rejected", level=logging.WARNING, reason="protected")

        assert _single_line(stream)["level"] == "WARNING"

    def test_non_json_values_are_stringified(
        self, logger: logging.Logger, stream: io.StringIO
    ) -> None:
        log_event(logger, "config.loaded", data_dir=Path("C:/data"))

        assert _single_line(stream)["data_dir"] == str(Path("C:/data"))

    def test_envelope_keys_cannot_be_overridden_by_fields(
        self, logger: logging.Logger, stream: io.StringIO
    ) -> None:
        log_event(logger, "real.event", ts="forged", level_name="x")

        record = _single_line(stream)

        assert record["ts"] != "forged"
        assert record["event"] == "real.event"
        assert record["level_name"] == "x"

    def test_exception_info_is_included(self, logger: logging.Logger, stream: io.StringIO) -> None:
        try:
            _fail_collector()
        except ValueError:
            logger.exception("collector.failed")

        exception_text = _single_line(stream)["exception"]

        assert isinstance(exception_text, str)
        assert "ValueError: boom" in exception_text

    def test_lines_are_bounded_and_remain_valid_json(self, stream: io.StringIO) -> None:
        bounded_logger = logging.getLogger("windows_medic.test.bounded")
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonLineFormatter(max_line_length=512))
        bounded_logger.addHandler(handler)
        bounded_logger.setLevel(logging.DEBUG)
        bounded_logger.propagate = False
        try:
            log_event(bounded_logger, "big.event", command_line="x" * 10_000, pid=7)
        finally:
            bounded_logger.removeHandler(handler)

        raw = stream.getvalue().splitlines()[0]
        record = json.loads(raw)

        assert len(raw) <= 512
        assert record["event"] == "big.event"
        assert record["truncated"] is True
        assert "command_line" not in record


class TestConfigureLogging:
    def test_installs_json_handler_on_root_at_requested_level(
        self, root_logger_state: None, stream: io.StringIO
    ) -> None:
        configure_logging(LogLevel.WARNING, stream)

        logging.getLogger("windows_medic.some.module").warning("pressure.suspect")
        logging.getLogger("windows_medic.some.module").info("ignored")

        assert _single_line(stream)["event"] == "pressure.suspect"

    def test_reconfiguring_replaces_the_previous_handler(
        self, root_logger_state: None, stream: io.StringIO
    ) -> None:
        configure_logging(LogLevel.INFO, io.StringIO())
        configure_logging(LogLevel.INFO, stream)

        logging.getLogger("windows_medic.x").info("once")

        assert _single_line(stream)["event"] == "once"

    def test_leaves_foreign_handlers_alone(
        self, root_logger_state: None, stream: io.StringIO
    ) -> None:
        foreign = logging.NullHandler()
        logging.getLogger().addHandler(foreign)

        configure_logging(LogLevel.INFO, stream)

        assert foreign in logging.getLogger().handlers
