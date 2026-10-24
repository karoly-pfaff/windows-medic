"""Structured event-logging convention shared by every layer above the domain.

An event is a stable dotted name (``incident.opened``, ``repair.rejected``) plus typed fields
carrying stable ids. The formatter that turns records into JSON lines lives in
infrastructure; this module only defines how fields are attached to a record.
"""

import logging

EVENT_FIELDS_ATTRIBUTE = "event_fields"


def log_event(
    logger: logging.Logger, event: str, *, level: int = logging.INFO, **fields: object
) -> None:
    """Log *event* with structured *fields* attached for the structured formatter."""
    logger.log(level, event, extra={EVENT_FIELDS_ATTRIBUTE: fields})
