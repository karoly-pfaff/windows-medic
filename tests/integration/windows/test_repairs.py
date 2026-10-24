"""Repairs against the real OS: only test-owned processes are ever targeted.

Every mutation goes through the exact-identity controller; the fixtures validate the
identities they observed before cleaning up, and never act on a PID alone.
"""

import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psutil
import pytest

from windows_medic.application.services.repair_audit_trail import RepairAuditTrail
from windows_medic.application.services.repair_executor import RepairExecutor, RepairLimits
from windows_medic.application.use_cases.clear_port import ClearPort
from windows_medic.application.use_cases.inspect_port import InspectPort
from windows_medic.application.use_cases.inspect_process import InspectionLimits
from windows_medic.application.use_cases.terminate_process import TerminateProcess
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import (
    MemberOutcome,
    RejectionReason,
    RepairScope,
    RepairStatus,
    RiskLevel,
)
from windows_medic.domain.policies.protection import ProtectionPolicy
from windows_medic.domain.policies.risk_markers import AncestryPolicy
from windows_medic.infrastructure.config.settings import DEFAULT_TERMINAL_PROCESS_NAMES
from windows_medic.infrastructure.persistence.sqlite_connection import open_database
from windows_medic.infrastructure.persistence.sqlite_repair_audit import (
    SqliteRepairAuditRepository,
)
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic.infrastructure.windows.component_controller import spawn_detached
from windows_medic.infrastructure.windows.process_controller import WindowsProcessController
from windows_medic.infrastructure.windows.psutil_network_reader import PsutilNetworkReader
from windows_medic.infrastructure.windows.windows_process_reader import WindowsProcessReader
from windows_medic_root.container import WINDOWS_MEDIC_MARKERS

pytestmark = pytest.mark.windows_integration

INTERPRETER = getattr(sys, "_base_executable", sys.executable)
TREE_SCRIPT = Path(__file__).with_name("process_tree_child.py")
CHILD_LISTENER = (
    "import socket, time; s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); "
    "print(s.getsockname()[1], flush=True); time.sleep(120)"
)


class Engine:
    """Real adapters over a temporary audit database."""

    def __init__(self, db_path: Path) -> None:
        clock = SystemClock()
        self.reader = WindowsProcessReader(clock)
        self.network = PsutilNetworkReader()
        self.database = open_database(db_path)
        self.audit = SqliteRepairAuditRepository(self.database)
        protection = ProtectionPolicy(
            own_pid=os.getpid(),
            windows_medic_markers=WINDOWS_MEDIC_MARKERS,
            user_protected_names=(),
            windows_directory=os.environ.get("SYSTEMROOT", "C:\\Windows"),
        )
        ancestry = AncestryPolicy(
            claude_markers=("claude",), terminal_process_names=DEFAULT_TERMINAL_PROCESS_NAMES
        )
        self.trail = RepairAuditTrail(audit=self.audit, clock=clock, retention=timedelta(days=1))
        self.executor = RepairExecutor(
            process_reader=self.reader,
            controller=WindowsProcessController(),
            trail=self.trail,
            protection=protection,
            ancestry=ancestry,
            limits=RepairLimits(
                verify_timeout=timedelta(seconds=10),
                verify_interval=timedelta(milliseconds=100),
                max_tree_members=50,
            ),
        )
        self.terminate = TerminateProcess(executor=self.executor)
        self.clear_port = ClearPort(
            inspect_port=InspectPort(
                process_reader=self.reader,
                network_reader=self.network,
                protection=protection,
                ancestry=ancestry,
                limits=InspectionLimits(max_ancestors=8, max_descendants=8, max_port_owners=8),
            ),
            network_reader=self.network,
            executor=self.executor,
        )

    def identity_of(self, pid: int) -> ProcessIdentity:
        [match] = [o for o in self.reader.snapshot().processes if o.identity.pid == pid]
        return match.identity

    def alive(self, identity: ProcessIdentity) -> bool:
        return self.reader.get(identity) is not None


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    built = Engine(tmp_path / "audit.sqlite3")
    try:
        yield built
    finally:
        built.database.close()


@pytest.fixture
def owned_tree(engine: Engine) -> Iterator[tuple[ProcessIdentity, list[ProcessIdentity]]]:
    """Root identity plus the identities of its three descendants; cleaned up by identity."""
    root = subprocess.Popen(
        [INTERPRETER, str(TREE_SCRIPT)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    identities: list[ProcessIdentity] = []
    try:
        assert root.stdout is not None
        pids = [int(token) for token in root.stdout.readline().split()]
        assert len(pids) == 3
        identities = [engine.identity_of(root.pid), *(engine.identity_of(pid) for pid in pids)]
        yield identities[0], identities[1:]
    finally:
        for identity in identities:
            _terminate_exact(identity)
        root.wait(timeout=30)
        if root.stdout is not None:
            root.stdout.close()


@pytest.fixture
def child_listener(engine: Engine) -> Iterator[tuple[ProcessIdentity, int]]:
    child = subprocess.Popen(
        [INTERPRETER, "-c", CHILD_LISTENER],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    identity: ProcessIdentity | None = None
    try:
        assert child.stdout is not None
        port = int(child.stdout.readline().strip())
        identity = engine.identity_of(child.pid)
        yield identity, port
    finally:
        if identity is not None:
            _terminate_exact(identity)
        child.wait(timeout=30)
        if child.stdout is not None:
            child.stdout.close()


def _terminate_exact(identity: ProcessIdentity) -> None:
    """Cleanup by validated identity (psutil's float create time, within 10 ms)."""
    try:
        process = psutil.Process(identity.pid)
        actual = datetime.fromtimestamp(process.create_time(), tz=UTC)
    except psutil.NoSuchProcess:
        return
    if abs((actual - identity.create_time).total_seconds()) < 0.01:
        process.terminate()
        process.wait(timeout=30)


class TestTerminate:
    def test_a_test_owned_tree_is_terminated_parents_first_and_verified(
        self, engine: Engine, owned_tree: tuple[ProcessIdentity, list[ProcessIdentity]]
    ) -> None:
        root, descendants = owned_tree

        record = engine.terminate.execute(root.pid, root.create_time, RepairScope.TREE)

        assert record.status is RepairStatus.SUCCEEDED, record
        assert record.risk in (RiskLevel.LOW, RiskLevel.MEDIUM)
        assert {m.identity for m in record.members} == {root, *descendants}
        assert all(m.outcome is MemberOutcome.TERMINATED for m in record.members)
        assert record.members[0].identity == root  # parents first: the target leads
        assert record.verification is not None
        assert record.verification.passed is True
        assert not any(engine.alive(identity) for identity in (root, *descendants))
        stored = engine.audit.get(record.id)
        assert stored == record

    def test_a_single_process_leaves_its_children_alone(
        self, engine: Engine, owned_tree: tuple[ProcessIdentity, list[ProcessIdentity]]
    ) -> None:
        root, descendants = owned_tree

        record = engine.terminate.execute(root.pid, root.create_time)

        assert record.status is RepairStatus.SUCCEEDED
        assert [m.identity for m in record.members] == [root]
        assert not engine.alive(root)
        assert all(engine.alive(identity) for identity in descendants)

    def test_a_stale_identity_is_rejected_and_nothing_is_touched(
        self, engine: Engine, owned_tree: tuple[ProcessIdentity, list[ProcessIdentity]]
    ) -> None:
        root, descendants = owned_tree

        record = engine.terminate.execute(root.pid, root.create_time + timedelta(seconds=1))

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.STALE_IDENTITY
        assert all(engine.alive(identity) for identity in (root, *descendants))

    def test_critical_and_self_targets_are_rejected_by_policy(self, engine: Engine) -> None:
        system = engine.identity_of(4)
        me = engine.identity_of(os.getpid())

        for identity in (system, me):
            record = engine.terminate.execute(identity.pid, identity.create_time)

            assert record.status is RepairStatus.REJECTED
            assert record.rejection is RejectionReason.TARGET_PROTECTED
            assert engine.alive(identity)

    def test_rejections_and_results_are_in_the_audit(
        self, engine: Engine, owned_tree: tuple[ProcessIdentity, list[ProcessIdentity]]
    ) -> None:
        root, _ = owned_tree
        engine.terminate.execute(root.pid, root.create_time + timedelta(seconds=1))
        engine.terminate.execute(root.pid, root.create_time, RepairScope.TREE)

        records = engine.audit.recent(limit=10)

        assert [r.status for r in records] == [RepairStatus.SUCCEEDED, RepairStatus.REJECTED]


class TestClearPort:
    def test_the_owner_is_terminated_and_the_port_freed(
        self, engine: Engine, child_listener: tuple[ProcessIdentity, int]
    ) -> None:
        owner, port = child_listener

        record = engine.clear_port.execute(port, expected_owner=owner)

        assert record.status is RepairStatus.SUCCEEDED, record
        assert record.port == port
        assert [m.identity for m in record.members] == [owner]
        assert record.verification is not None
        assert record.verification.passed is True
        assert f"port {port} has no listener" in record.verification.detail
        assert not engine.alive(owner)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))  # the port is really free again

    def test_a_port_nobody_listens_on_is_rejected(self, engine: Engine) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = int(probe.getsockname()[1])

        record = engine.clear_port.execute(free_port)

        assert record.status is RepairStatus.REJECTED
        assert record.rejection is RejectionReason.PORT_NOT_LISTENING

    def test_a_changed_owner_is_rejected(
        self, engine: Engine, child_listener: tuple[ProcessIdentity, int]
    ) -> None:
        owner, port = child_listener
        somebody_else = ProcessIdentity(owner.pid, owner.create_time + timedelta(seconds=1))

        record = engine.clear_port.execute(port, expected_owner=somebody_else)

        assert record.rejection is RejectionReason.PORT_OWNER_CHANGED
        assert engine.alive(owner)


class TestConsoleScript:
    def test_terminate_and_repairs_through_the_cli(
        self,
        engine: Engine,
        owned_tree: tuple[ProcessIdentity, list[ProcessIdentity]],
        tmp_path: Path,
    ) -> None:
        root, descendants = owned_tree
        scripts = Path(sys.executable).parent
        environ = {**os.environ, "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data")}

        terminated = subprocess.run(
            [
                str(scripts / "windows-medic.exe"),
                "terminate",
                str(root.pid),
                "--create-time",
                root.create_time.isoformat(),
                "--tree",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=environ,
            timeout=60,
        )
        assert terminated.returncode == 0, terminated.stderr
        assert "process.terminate_tree" in terminated.stdout
        assert "-> succeeded" in terminated.stdout
        assert not any(engine.alive(identity) for identity in (root, *descendants))

        listed = subprocess.run(
            [str(scripts / "windows-medic.exe"), "repairs"],
            capture_output=True,
            text=True,
            check=False,
            env=environ,
            timeout=60,
        )
        assert listed.returncode == 0, listed.stderr
        assert listed.stdout.startswith("Recent repairs: 1 (newest first)")
        assert "succeeded" in listed.stdout


class TestSpawnDetached:
    def test_starts_an_argument_array_detached_and_returns_its_pid(self, engine: Engine) -> None:
        pid = spawn_detached([INTERPRETER, "-c", "import time; time.sleep(60)"])
        identity = engine.identity_of(pid)
        try:
            assert engine.alive(identity)
        finally:
            _terminate_exact(identity)
        assert not engine.alive(identity)
