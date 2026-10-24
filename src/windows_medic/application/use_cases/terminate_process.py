"""Terminate one exact process identity, or its tree. Explicit, never automatic."""

from datetime import datetime

from windows_medic.application.services.repair_executor import RepairExecutor, RepairRequest
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import RepairAction, RepairRecord, RepairScope


class TerminateProcess:
    """``process.terminate`` / ``process.terminate_tree`` over the repair executor."""

    def __init__(self, *, executor: RepairExecutor) -> None:
        self._executor = executor

    @property
    def executor(self) -> RepairExecutor:
        return self._executor

    def execute(
        self, pid: int, create_time: datetime, scope: RepairScope = RepairScope.PROCESS
    ) -> RepairRecord:
        """Terminate ``(pid, create_time)``; a PID alone is never enough.

        Raises:
            ValueError: If *pid* is negative or *create_time* is naive (boundary bugs).
            RepairAuditError: If the intended action could not be recorded; nothing mutated.
        """
        identity = ProcessIdentity(pid, create_time)
        action = (
            RepairAction.PROCESS_TERMINATE_TREE
            if scope is RepairScope.TREE
            else RepairAction.PROCESS_TERMINATE
        )
        return self._executor.execute(RepairRequest(action, scope, (identity,)))
