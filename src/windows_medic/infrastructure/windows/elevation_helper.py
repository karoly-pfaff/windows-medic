"""``windows-medic-elevated``: the one-shot elevated helper.

Launched with administrator rights by the unelevated process for exactly one allowlisted
recipe. It re-derives every fact itself: it parses the typed arguments strictly, reads the
live process table, checks that the requested identity still exists, *is* the component
the recipe names and lives in the requested session, and only then terminates that exact
identity. It never receives an executable, a command line or a name to act on. The
outcome is written to the result file the caller provided; the exit code mirrors it.
"""

import re
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from windows_medic.application.operations import ELEVATED_RESULT_PREFIX
from windows_medic.application.ports.process_reader import ProcessReader
from windows_medic.domain.errors import ObservationError
from windows_medic.domain.models.component import WindowsComponent
from windows_medic.domain.models.elevation import (
    ElevatedOutcome,
    ElevatedRecipe,
    ElevatedRejection,
    ElevatedRequest,
    ElevatedResult,
)
from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import TerminationAttempt
from windows_medic.infrastructure.time.system_clock import SystemClock
from windows_medic.infrastructure.windows.elevation_protocol import (
    RESULT_SUFFIX,
    encode_result,
    parse_request,
    result_path_of,
)
from windows_medic.infrastructure.windows.process_controller import terminate_exact
from windows_medic.infrastructure.windows.windows_process_reader import WindowsProcessReader

PROGRAM = "windows-medic-elevated"
EXIT_COMPLETED = 0
EXIT_FAILED = 1
EXIT_REJECTED = 2

_COMPONENT_FOR_RECIPE = {ElevatedRecipe.WINDOWS_DWM_TERMINATE: WindowsComponent.DWM}
# What the launcher names result files: elevated-<uuid4 hex>.json.
_RESULT_NAME = re.compile(
    re.escape(ELEVATED_RESULT_PREFIX) + "[0-9a-f]{32}" + re.escape(RESULT_SUFFIX)
)


def perform(
    request: ElevatedRequest,
    *,
    process_reader: ProcessReader,
    terminate: Callable[[ProcessIdentity], TerminationAttempt] = terminate_exact,
) -> ElevatedResult:
    """Carry out *request* after verifying every precondition against the live table."""
    component = _COMPONENT_FOR_RECIPE[request.recipe]
    try:
        snapshot = process_reader.snapshot()
    except ObservationError as exc:
        return ElevatedResult(ElevatedOutcome.FAILED, detail=f"process inventory failed: {exc}")
    current = next((o for o in snapshot.processes if o.identity.pid == request.target.pid), None)
    if current is None:
        return ElevatedResult(
            ElevatedOutcome.REJECTED, rejection=ElevatedRejection.TARGET_NOT_FOUND
        )
    if current.identity != request.target:
        return ElevatedResult(ElevatedOutcome.REJECTED, rejection=ElevatedRejection.STALE_IDENTITY)
    if not available(current.name) or current.name.lower() != component.image_name:
        return ElevatedResult(
            ElevatedOutcome.REJECTED, rejection=ElevatedRejection.NOT_THE_COMPONENT
        )
    if not available(current.session_id) or current.session_id != request.session:
        return ElevatedResult(
            ElevatedOutcome.REJECTED, rejection=ElevatedRejection.SESSION_MISMATCH
        )
    return ElevatedResult(ElevatedOutcome.COMPLETED, termination=terminate(request.target))


def main(
    argv: Sequence[str] | None = None,
    *,
    process_reader: ProcessReader | None = None,
    terminate: Callable[[ProcessIdentity], TerminationAttempt] = terminate_exact,
    stderr: TextIO | None = None,
) -> int:
    """Entry point. Writes the result file when the arguments name one; exit code mirrors it."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    stderr = sys.stderr if stderr is None else stderr
    result_path = result_path_of(arguments)
    parsed = parse_request(arguments)
    if isinstance(parsed, ElevatedRejection):
        result = ElevatedResult(ElevatedOutcome.REJECTED, rejection=parsed)
    else:
        request, result_path = parsed
        reader = WindowsProcessReader(SystemClock()) if process_reader is None else process_reader
        try:
            result = perform(request, process_reader=reader, terminate=terminate)
        except Exception as exc:  # noqa: BLE001 - process boundary: report, never traceback
            result = ElevatedResult(ElevatedOutcome.FAILED, detail=f"{type(exc).__name__}: {exc}")
    if result_path is not None:
        try:
            write_result(result_path, encode_result(result))
        except OSError as exc:
            stderr.write(f"{PROGRAM}: cannot write result file {result_path}: {exc}\n")
            return EXIT_FAILED
    else:
        stderr.write(f"{PROGRAM}: {encode_result(result)}\n")
    return _exit_code(result)


def write_result(path: Path, text: str) -> None:
    """Write the result as administrator only where the unelevated caller cannot redirect it.

    The path comes from the caller: it must name a fresh ``elevated-<uuid>.json``, sit in a
    directory reached without junctions or symbolic links, and is created exclusively, so
    the elevated write can neither land elsewhere nor replace an existing file.

    Raises:
        OSError: When the path is not acceptable or cannot be written.
    """
    if not _RESULT_NAME.fullmatch(path.name):
        raise OSError(f"{path.name!r} is not a result file name")
    for directory in (path.parent, *path.parent.parents):
        if directory.is_junction() or directory.is_symlink():
            raise OSError(f"{path.parent} is reached through a link ({directory})")
    with path.open("x", encoding="utf-8") as stream:
        stream.write(text)


def _exit_code(result: ElevatedResult) -> int:
    if result.outcome is ElevatedOutcome.COMPLETED:
        return EXIT_COMPLETED
    if result.outcome is ElevatedOutcome.REJECTED:
        return EXIT_REJECTED
    return EXIT_FAILED


def helper_executable() -> Path:
    """The console script installed next to the interpreter."""
    return Path(sys.executable).parent / f"{PROGRAM}.exe"
