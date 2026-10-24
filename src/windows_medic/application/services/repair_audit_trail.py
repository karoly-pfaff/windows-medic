"""The audit discipline every repair follows: intent before mutation, outcome after.

The intended action must be durable before anything is touched; a repair whose intent
cannot be recorded is not attempted (``RepairAuditError``). A final write that fails is
logged and the result is still returned to the caller — the mutation happened, hiding it
would be worse. Rejections are recorded too. Retention is applied after every outcome.
"""

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timedelta

from windows_medic.application.observability import log_event
from windows_medic.application.ports.clock import Clock
from windows_medic.application.ports.repair_audit import RepairAuditRepository
from windows_medic.domain.errors import RepairAuditError
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import (
    RejectionReason,
    RepairAction,
    RepairRecord,
    RepairScope,
    RepairStatus,
    RiskLevel,
    new_repair_id,
)

_logger = logging.getLogger(__name__)


class RepairAuditTrail:
    def __init__(
        self,
        *,
        audit: RepairAuditRepository,
        clock: Clock,
        retention: timedelta,
        ids: Callable[[], str] = new_repair_id,
    ) -> None:
        if retention <= timedelta(0):
            raise ValueError("retention must be positive")
        self._audit = audit
        self._clock = clock
        self._retention = retention
        self._ids = ids
        self._exclusive = threading.Lock()

    @property
    def clock(self) -> Clock:
        return self._clock

    @property
    def exclusive(self) -> threading.Lock:
        """Held for the whole of one repair: plan, act and verify of two repairs in this
        process (parallel MCP tool calls) never interleave."""
        return self._exclusive

    def new_id(self) -> str:
        return self._ids()

    def record_intent(self, record: RepairRecord, *, planned_members: int) -> None:
        """Persist the intended action; raises RepairAuditError so nothing is mutated."""
        self._audit.save(record)
        log_event(
            _logger,
            "repair.started",
            repair_id=record.id,
            action=record.action.value,
            scope=record.scope.value,
            target=None if record.target is None else str(record.target),
            risk=None if record.risk is None else record.risk.value,
            members=planned_members,
        )

    def record_outcome(self, record: RepairRecord) -> None:
        """Persist the outcome; a failing write is logged, never raised."""
        log_event(
            _logger,
            "repair.completed",
            repair_id=record.id,
            action=record.action.value,
            status=record.status.value,
            gone=sum(1 for m in record.members if m.outcome.gone),
            members=len(record.members),
            appeared=len(record.appeared),
            replacement=None if record.replacement is None else str(record.replacement),
        )
        self._persist_final(record)

    def reject(
        self,
        *,
        action: RepairAction,
        scope: RepairScope,
        target: ProcessIdentity | None,
        reason: RejectionReason,
        port: int | None = None,
        risk: RiskLevel | None = None,
        requires_elevation: bool = False,
        record_id: str | None = None,
        requested_at: datetime | None = None,
    ) -> RepairRecord:
        """Record a rejection decided by policy (nothing is mutated)."""
        record = RepairRecord(
            id=self._ids() if record_id is None else record_id,
            action=action,
            scope=scope,
            status=RepairStatus.REJECTED,
            requested_at=self._clock.now() if requested_at is None else requested_at,
            completed_at=self._clock.now(),
            target=target,
            port=port,
            risk=risk,
            requires_elevation=requires_elevation,
            rejection=reason,
            members=(),
            appeared=(),
            verification=None,
        )
        self._persist_final(record)
        log_event(
            _logger,
            "repair.rejected",
            level=logging.WARNING,
            repair_id=record.id,
            action=action.value,
            target=None if target is None else str(target),
            port=port,
            reason=reason.value,
        )
        return record

    def _persist_final(self, record: RepairRecord) -> None:
        try:
            self._audit.save(record)
            self._audit.purge_older_than(record.requested_at - self._retention)
        except RepairAuditError as exc:
            log_event(
                _logger,
                "repair.audit_failed",
                level=logging.ERROR,
                repair_id=record.id,
                status=record.status.value,
                error=str(exc),
            )
