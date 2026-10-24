"""``windows-medic-agent`` / ``windows-medic-agentw`` entry point.

Runs the monitoring supervisor until Ctrl+C or, with ``--duration``, for a bounded time.
All diagnostics go to stderr as structured JSON and, with ``--log-file``, to a bounded
rotating file; stdout stays silent. The ``agentw`` launcher runs without a console (the
logon task uses it), in which case the standard streams do not exist and the log file is
the only output. Only one agent runs per data directory; a second start exits with
:data:`EXIT_ALREADY_RUNNING` and does nothing else.
"""

import argparse
import asyncio
import contextlib
import logging
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

import windows_medic
from windows_medic.application.observability import log_event
from windows_medic_agent.monitor import Monitor
from windows_medic_agent.wiring import build_monitor
from windows_medic_root.container import (
    EXIT_CONFIGURATION_ERROR,
    Container,
    try_compose,
    utf8_text,
)

PROGRAM = "windows-medic-agent"
EXIT_ALREADY_RUNNING = 3

_logger = logging.getLogger(__name__)


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    build: Callable[[Container], Monitor] = build_monitor,
) -> int:
    """Run the agent and return the process exit code."""
    environ = os.environ if environ is None else environ
    with contextlib.ExitStack() as streams:
        stdout = _stream(stdout, sys.stdout, streams)
        stderr = utf8_text(_stream(stderr, sys.stderr, streams))
        return _run(argv, environ=environ, stdout=stdout, stderr=stderr, build=build)


def _stream(given: TextIO | None, standard: TextIO | None, streams: contextlib.ExitStack) -> TextIO:
    """*given*, else the standard stream, else a null sink (no console under pythonw)."""
    if given is not None:
        return given
    if standard is not None:
        return standard
    return streams.enter_context(Path(os.devnull).open("w", encoding="utf-8"))


def _run(
    argv: Sequence[str] | None,
    *,
    environ: Mapping[str, str],
    stdout: TextIO,
    stderr: TextIO,
    build: Callable[[Container], Monitor],
) -> int:
    parser = argparse.ArgumentParser(
        prog=PROGRAM, description="Windows Medic background monitoring agent."
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    parser.add_argument(
        "--duration",
        type=_positive_seconds,
        default=None,
        metavar="SECONDS",
        help="stop after this many seconds instead of running until Ctrl+C",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="also write structured JSON logs to this rotating file "
        "(the logon task passes <data_dir>\\logs\\windows-medic-agent.log)",
    )
    arguments = parser.parse_args(argv)

    if arguments.version:
        stdout.write(f"{PROGRAM} {windows_medic.__version__}\n")
        return 0

    container = try_compose(
        PROGRAM,
        environ=environ,
        log_stream=stderr,
        error_stream=stderr,
        log_file=arguments.log_file,
    )
    if container is None:
        return EXIT_CONFIGURATION_ERROR

    try:
        lease = container.instance_guard.try_acquire()
        if lease is None:
            log_event(
                _logger, "agent.already_running", pid=os.getpid(), exit_code=EXIT_ALREADY_RUNNING
            )
            return EXIT_ALREADY_RUNNING
        try:
            return _serve_until_done(container, build, arguments.duration)
        finally:
            lease.release()
    finally:
        container.close()


def _serve_until_done(
    container: Container, build: Callable[[Container], Monitor], duration: float | None
) -> int:
    monitor = build(container)
    log_event(
        _logger,
        "agent.started",
        pid=os.getpid(),
        duration_seconds=duration,
        system_interval_seconds=container.settings.sampling.system_interval_seconds,
        process_interval_seconds=container.settings.sampling.process_interval_seconds,
    )
    try:
        asyncio.run(_serve(monitor, duration))
    except KeyboardInterrupt:
        log_event(_logger, "agent.stopped", reason="interrupted")
        return 0
    log_event(_logger, "agent.stopped", reason="duration elapsed")
    return 0


async def _serve(monitor: Monitor, duration: float | None) -> None:
    stop = asyncio.Event()
    if duration is not None:
        asyncio.get_running_loop().call_later(duration, stop.set)
    await monitor.run(stop)


def _positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a number of seconds: {value!r}") from exc
    if seconds <= 0:
        raise argparse.ArgumentTypeError("duration must be positive")
    return seconds
