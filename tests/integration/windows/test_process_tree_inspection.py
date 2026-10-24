"""InspectProcess against the live process tree.

Only test-owned children are created. The orphan test terminates its grandchild through
psutil after validating the exact identity it observed (never by PID alone).
"""

import os
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import psutil
import pytest

from windows_medic.application.use_cases.inspect_process import InspectionLimits, InspectProcess
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.tree import UnresolvedParent
from windows_medic.domain.policies.protection import (
    ProtectionLevel,
    ProtectionPolicy,
    ProtectionReason,
)
from windows_medic.domain.policies.risk_markers import AncestryPolicy, RiskMarker
from windows_medic.infrastructure.config.settings import DEFAULT_TERMINAL_PROCESS_NAMES
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic.infrastructure.windows.windows_process_reader import WindowsProcessReader
from windows_medic_root.container import WINDOWS_MEDIC_MARKERS

pytestmark = pytest.mark.windows_integration

INTERPRETER = getattr(sys, "_base_executable", sys.executable)
SLEEPER = "import time; time.sleep(120)"
# Spawns a sleeping grandchild, prints its pid, then exits so the grandchild is orphaned.
ORPHANER = (
    "import subprocess, sys; "
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'], "
    "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
    "print(p.pid, flush=True)"
)


@pytest.fixture
def inspect() -> InspectProcess:
    return InspectProcess(
        process_reader=WindowsProcessReader(SystemClock()),
        protection=ProtectionPolicy(
            own_pid=os.getpid(),
            windows_medic_markers=WINDOWS_MEDIC_MARKERS,
            user_protected_names=(),
            windows_directory=os.environ.get("SYSTEMROOT", "C:\\Windows"),
        ),
        ancestry=AncestryPolicy(
            claude_markers=("claude",), terminal_process_names=DEFAULT_TERMINAL_PROCESS_NAMES
        ),
        limits=InspectionLimits(max_ancestors=16, max_descendants=50),
    )


@pytest.fixture
def sleeper() -> Iterator[subprocess.Popen[bytes]]:
    child = subprocess.Popen([INTERPRETER, "-c", SLEEPER])
    try:
        yield child
    finally:
        child.terminate()
        child.wait(timeout=30)


@pytest.fixture
def orphan() -> Iterator[int]:
    """PID of a live grandchild whose parent has already exited."""
    completed = subprocess.run(
        [INTERPRETER, "-c", ORPHANER], capture_output=True, text=True, check=True, timeout=60
    )
    pid = int(completed.stdout.strip())
    observed: ProcessIdentity | None = None
    try:
        reader = WindowsProcessReader(SystemClock())
        [match] = [p for p in reader.snapshot().processes if p.identity.pid == pid]
        observed = match.identity
        yield pid
    finally:
        if observed is not None:
            _terminate_exact(observed)


def _terminate_exact(identity: ProcessIdentity) -> None:
    try:
        process = psutil.Process(identity.pid)
        actual = datetime.fromtimestamp(process.create_time(), tz=UTC)
    except psutil.NoSuchProcess:
        return
    if abs((actual - identity.create_time).total_seconds()) < 0.01:
        process.terminate()
        process.wait(timeout=30)


class TestTreeLinks:
    def test_child_links_to_this_process_and_appears_among_its_descendants(
        self, inspect: InspectProcess, sleeper: subprocess.Popen[bytes]
    ) -> None:
        child = inspect.execute(sleeper.pid)
        me = inspect.execute(os.getpid())

        assert child.parent == me.observation.identity
        assert child.ancestors[0].identity == me.observation.identity
        assert sleeper.pid in {d.identity.pid for d in me.descendants}
        assert me.protection.level is ProtectionLevel.PROTECTED
        assert ProtectionReason.WINDOWS_MEDIC_SELF in me.protection.reasons
        assert RiskMarker.WINDOWS_MEDIC_ANCESTRY in child.risk_markers

    def test_exact_create_time_is_enforced(
        self, inspect: InspectProcess, sleeper: subprocess.Popen[bytes]
    ) -> None:
        identity = inspect.execute(sleeper.pid).observation.identity

        assert inspect.execute(sleeper.pid, identity.create_time).observation.identity == identity

    def test_orphaned_grandchild_has_unresolved_parent_evidence(
        self, inspect: InspectProcess, orphan: int
    ) -> None:
        inspection = inspect.execute(orphan)

        assert isinstance(inspection.parent, UnresolvedParent)
        assert RiskMarker.UNRESOLVED_PARENT in inspection.risk_markers
        assert inspection.ancestors == ()


class TestProtectionOnRealProcesses:
    def test_system_process_is_critical(self, inspect: InspectProcess) -> None:
        system = inspect.execute(4)

        assert system.protection.level is ProtectionLevel.CRITICAL
        assert system.observation.name == "System"

    def test_ancestry_walk_reaches_a_root_without_exploding(self, inspect: InspectProcess) -> None:
        me = inspect.execute(os.getpid())

        assert 1 <= len(me.ancestors) <= 16
        assert me.ancestors_truncated is False


def test_inspect_console_script_end_to_end(
    sleeper: subprocess.Popen[bytes], tmp_path: Path
) -> None:
    executable = Path(sys.executable).parent / "windows-medic.exe"
    environ = {**os.environ, "WINDOWS_MEDIC_DATA_DIR": str(tmp_path / "data")}

    completed = subprocess.run(
        [str(executable), "inspect", str(sleeper.pid)],
        capture_output=True,
        text=True,
        check=False,
        env=environ,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.startswith(f"Process python.exe (pid {sleeper.pid}")
    assert f"Parent: python.exe (pid {os.getpid()})" in completed.stdout
    assert "Protection:" in completed.stdout
    assert completed.stdout.count("\n") < 120, "output must stay bounded"
