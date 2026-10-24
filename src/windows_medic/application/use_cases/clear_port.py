"""Clear a TCP port: terminate its confirmed owner(s), then verify nothing listens.

The owner is resolved immediately before mutation with the same race-safe procedure as
``inspect_port`` (baseline snapshot, listener table, identity re-resolution), the clear-port
policy decides eligibility, and the executor revalidates every identity again on its own
fresh snapshot. Afterwards the listener table is read back: a listener that remains is a
failed postcondition, and a *different* owner is reported distinctly from a survivor.
"""

from windows_medic.application.ports.clock import Clock
from windows_medic.application.ports.network_reader import NetworkReader
from windows_medic.application.services.repair_executor import RepairExecutor, RepairRequest
from windows_medic.application.use_cases.inspect_port import InspectPort
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import (
    RejectionReason,
    RepairAction,
    RepairRecord,
    RepairScope,
    Verification,
)
from windows_medic.domain.policies.port_clearing import ClearPortBlocker

_REJECTION_FOR_BLOCKER = {
    ClearPortBlocker.OWNER_PROTECTED: RejectionReason.PORT_OWNER_PROTECTED,
    ClearPortBlocker.OWNER_UNRESOLVED: RejectionReason.PORT_OWNER_UNRESOLVED,
    ClearPortBlocker.NO_OWNER: RejectionReason.PORT_NOT_LISTENING,
}


class ClearPort:
    """``port.clear`` over the repair executor."""

    def __init__(
        self,
        *,
        inspect_port: InspectPort,
        network_reader: NetworkReader,
        executor: RepairExecutor,
    ) -> None:
        self._inspect_port = inspect_port
        self._network_reader = network_reader
        self._executor = executor

    @property
    def executor(self) -> RepairExecutor:
        return self._executor

    def execute(self, port: int, expected_owner: ProcessIdentity | None = None) -> RepairRecord:
        """Clear *port*; when *expected_owner* is given the port must still belong to it.

        Raises:
            ValueError: If *port* is out of range (a boundary bug).
            RepairAuditError: If the intended action could not be recorded; nothing mutated.
        """
        inspection = self._inspect_port.execute(port)
        owners = tuple(o.identity for o in inspection.owners)
        trail = self._executor.trail
        if expected_owner is not None and expected_owner not in owners:
            return trail.reject(
                action=RepairAction.PORT_CLEAR,
                scope=RepairScope.PROCESS,
                target=expected_owner,
                port=port,
                reason=RejectionReason.PORT_OWNER_CHANGED,
            )
        if not inspection.clear_port.eligible:
            return trail.reject(
                action=RepairAction.PORT_CLEAR,
                scope=RepairScope.PROCESS,
                target=owners[0] if owners else None,
                port=port,
                reason=_REJECTION_FOR_BLOCKER[inspection.clear_port.blockers[0]],
            )
        request = RepairRequest(RepairAction.PORT_CLEAR, RepairScope.PROCESS, owners, port=port)
        clock = trail.clock
        return self._executor.execute(
            request, postcondition=lambda: self._port_state(port, owners, clock)
        )

    def _port_state(
        self, port: int, owners: tuple[ProcessIdentity, ...], clock: Clock
    ) -> Verification:
        listeners = [e for e in self._network_reader.tcp_listeners() if e.port == port]
        checked_at = clock.now()
        if not listeners:
            return Verification(True, f"port {port} has no listener", checked_at)
        pids = sorted({e.owner_pid for e in listeners if e.owner_pid is not None})
        original = {o.pid for o in owners}
        listed = ", ".join(f"pid {pid}" for pid in pids) or "owner unknown"
        if pids and not any(pid in original for pid in pids):
            detail = f"port {port} is now listened on by a different owner ({listed})"
        else:
            detail = f"port {port} still has a listener ({listed})"
        return Verification(False, detail, checked_at)
