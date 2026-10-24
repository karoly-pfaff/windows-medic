"""InspectPort against the live TCP table.

Listeners are created by this suite (in this process or a test-owned child) on loopback
ephemeral ports; nothing else on the machine is touched.
"""

import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from windows_medic.application.use_cases.inspect_port import InspectPort
from windows_medic.application.use_cases.inspect_process import InspectionLimits
from windows_medic.domain.models.metric import available
from windows_medic.domain.policies.port_clearing import ClearPortBlocker
from windows_medic.domain.policies.protection import ProtectionLevel, ProtectionPolicy
from windows_medic.domain.policies.risk_markers import AncestryPolicy
from windows_medic.infrastructure.config.settings import DEFAULT_TERMINAL_PROCESS_NAMES
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic.infrastructure.windows.psutil_network_reader import PsutilNetworkReader
from windows_medic.infrastructure.windows.windows_process_reader import WindowsProcessReader
from windows_medic_root.container import WINDOWS_MEDIC_MARKERS

pytestmark = pytest.mark.windows_integration

INTERPRETER = getattr(sys, "_base_executable", sys.executable)
CHILD_LISTENER = (
    "import socket, time; s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(); "
    "print(s.getsockname()[1], flush=True); time.sleep(120)"
)


@pytest.fixture
def inspect() -> InspectPort:
    return InspectPort(
        process_reader=WindowsProcessReader(SystemClock()),
        network_reader=PsutilNetworkReader(),
        protection=ProtectionPolicy(
            own_pid=os.getpid(),
            windows_medic_markers=WINDOWS_MEDIC_MARKERS,
            user_protected_names=(),
            windows_directory=os.environ.get("SYSTEMROOT", "C:\\Windows"),
        ),
        ancestry=AncestryPolicy(
            claude_markers=("claude",), terminal_process_names=DEFAULT_TERMINAL_PROCESS_NAMES
        ),
        limits=InspectionLimits(max_ancestors=8, max_descendants=8, max_port_owners=8),
    )


@pytest.fixture
def own_listener() -> Iterator[int]:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        yield server.getsockname()[1]


@pytest.fixture
def child_listener() -> Iterator[tuple[subprocess.Popen[str], int]]:
    child = subprocess.Popen([INTERPRETER, "-c", CHILD_LISTENER], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout is not None
        port = int(child.stdout.readline().strip())
        yield child, port
    finally:
        child.terminate()
        child.wait(timeout=30)
        if child.stdout is not None:
            child.stdout.close()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class TestOwnership:
    def test_child_listener_resolves_to_its_exact_identity_and_is_eligible(
        self, inspect: InspectPort, child_listener: tuple[subprocess.Popen[str], int]
    ) -> None:
        child, port = child_listener

        inspection = inspect.execute(port)

        [owner] = inspection.owners
        assert owner.identity.pid == child.pid
        assert owner.identity.create_time.tzinfo is not None
        assert available(owner.name)
        assert owner.name.lower() == "python.exe"
        assert [e.port for e in owner.endpoints] == [port]
        assert owner.parent is not None
        assert owner.protection.level is ProtectionLevel.NONE
        assert inspection.unresolved == ()
        assert inspection.clear_port.eligible is True

    def test_own_listener_is_protected_so_no_plan_is_offered(
        self, inspect: InspectPort, own_listener: int
    ) -> None:
        inspection = inspect.execute(own_listener)

        [owner] = inspection.owners
        assert owner.identity.pid == os.getpid()
        assert owner.protection.level is ProtectionLevel.PROTECTED
        assert inspection.clear_port.eligible is False
        assert inspection.clear_port.blockers == (ClearPortBlocker.OWNER_PROTECTED,)

    def test_closed_port_is_unowned(self, inspect: InspectPort) -> None:
        inspection = inspect.execute(_free_port())

        assert inspection.owners == ()
        assert inspection.unresolved == ()
        assert inspection.clear_port.blockers == (ClearPortBlocker.NO_OWNER,)

    def test_port_is_unowned_once_the_listener_exits(
        self, inspect: InspectPort, child_listener: tuple[subprocess.Popen[str], int]
    ) -> None:
        child, port = child_listener
        child.terminate()
        child.wait(timeout=30)

        inspection = inspect.execute(port)

        assert inspection.owners == ()
        assert inspection.unresolved == ()

    def test_system_service_owner_is_marked_protected(self, inspect: InspectPort) -> None:
        inspection = inspect.execute(135)  # RPC endpoint mapper, present on every Windows
        if not inspection.owners:
            pytest.skip("no listener on TCP 135 on this machine")

        [owner] = inspection.owners
        assert owner.protection.level >= ProtectionLevel.WINDOWS_COMPONENT
        assert inspection.clear_port.eligible is False
        assert ClearPortBlocker.OWNER_PROTECTED in inspection.clear_port.blockers


def test_port_console_script_end_to_end(
    child_listener: tuple[subprocess.Popen[str], int], tmp_path: Path
) -> None:
    child, port = child_listener
    executable = Path(sys.executable).parent / "windows-medic.exe"
    environ = {**os.environ, "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data")}

    completed = subprocess.run(
        [str(executable), "port", str(port)],
        capture_output=True,
        text=True,
        check=False,
        env=environ,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith(f"TCP port {port}")
    assert f"python.exe (pid {child.pid}" in completed.stdout
    assert "Clear-port plan: eligible" in completed.stdout
    assert completed.stdout.count("\n") < 40, "output must stay bounded"
