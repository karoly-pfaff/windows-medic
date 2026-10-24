"""Child process for the repair integration tests: a small test-owned process tree.

Spawns two children, one of which spawns a grandchild, prints all three PIDs on one line
and then sleeps. Every process in the tree is a plain Python sleeper created here, so the
tests never target anything they do not own. Terminated by the tests.
"""

import subprocess
import sys
import time

SLEEPER = "import time; time.sleep(120)"
SPAWNER = (
    "import subprocess, sys, time; "
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'], "
    "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
    "print(p.pid, flush=True); time.sleep(120)"
)


def main() -> int:
    leaf = subprocess.Popen(
        [sys.executable, "-c", SLEEPER],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    middle = subprocess.Popen(
        [sys.executable, "-c", SPAWNER],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert middle.stdout is not None
    grandchild = int(middle.stdout.readline().strip())
    sys.stdout.write(f"{leaf.pid} {middle.pid} {grandchild}\n")
    sys.stdout.flush()
    time.sleep(120)
    return 0


if __name__ == "__main__":
    sys.exit(main())
