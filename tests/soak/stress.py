"""Bounded load generators. Every child is test-owned, self-terminating and killed on exit.

Children are started from the base interpreter (not the venv launcher) so that each
generator is exactly one process the caller can account for.
"""

import contextlib
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

INTERPRETER = getattr(sys, "_base_executable", sys.executable)
CREATE_NO_WINDOW = 0x0800_0000

# Spins one core until its deadline; exits on its own even if the parent disappears.
_BURNER = (
    "import sys, time\n"
    "deadline = time.monotonic() + float(sys.argv[1])\n"
    "while time.monotonic() < deadline:\n"
    "    pass\n"
)
# Allocates and touches N bytes, reports, then holds them until its deadline.
_HOLDER = (
    "import sys, time\n"
    "size, seconds = int(sys.argv[1]), float(sys.argv[2])\n"
    "block = bytearray(size)\n"
    "for offset in range(0, size, 4096):\n"
    "    block[offset] = 1\n"
    "print('held', flush=True)\n"
    "time.sleep(seconds)\n"
)


def _quiet(command: list[str], *, stdout: int = subprocess.DEVNULL) -> subprocess.Popen[str]:
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=subprocess.DEVNULL,
        text=True,
        creationflags=CREATE_NO_WINDOW,
    )


def _reap(children: list[subprocess.Popen[str]]) -> None:
    for child in children:
        if child.poll() is None:
            child.kill()
    for child in children:
        child.wait(timeout=30)
        if child.stdout is not None:
            child.stdout.close()


@contextlib.contextmanager
def cpu_burn(*, workers: int, seconds: float) -> Iterator[list[subprocess.Popen[str]]]:
    """Spin *workers* cores for at most *seconds*; killed when the block exits."""
    children = [_quiet([INTERPRETER, "-c", _BURNER, str(seconds)]) for _ in range(workers)]
    try:
        yield children
    finally:
        _reap(children)


@contextlib.contextmanager
def memory_hold(*, size_bytes: int, seconds: float) -> Iterator[subprocess.Popen[str]]:
    """Commit *size_bytes* in a child for at most *seconds*; yields once the pages are touched."""
    child = _quiet(
        [INTERPRETER, "-c", _HOLDER, str(size_bytes), str(seconds)], stdout=subprocess.PIPE
    )
    try:
        assert child.stdout is not None
        line = child.stdout.readline().strip()
        if line != "held":
            raise RuntimeError(f"memory holder did not start: {line!r}")
        yield child
    finally:
        _reap([child])


@dataclass
class ChurnCounter:
    spawned: int = 0
    exited: int = 0


class ProcessChurn:
    """Spawns batches of short-lived processes from a thread until stopped.

    Rapid spawn/exit cycles recycle PIDs and make processes vanish between the kernel
    inventory and the per-process reads, which is the race the agent must survive.
    """

    def __init__(self, *, batch: int, pause_seconds: float) -> None:
        self._batch = batch
        self._pause = pause_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="process-churn", daemon=True)
        self.counter = ChurnCounter()

    def _run(self) -> None:
        while not self._stop.is_set():
            children = [_quiet([INTERPRETER, "-I", "-S", "-c", "pass"]) for _ in range(self._batch)]
            self.counter.spawned += len(children)
            for child in children:
                child.wait(timeout=60)
            self.counter.exited += len(children)
            self._stop.wait(self._pause)

    def __enter__(self) -> "ProcessChurn":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=120)


def wait_until(
    condition: Callable[[], bool], *, deadline_seconds: float, step: float = 0.1
) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(step)
    return False
