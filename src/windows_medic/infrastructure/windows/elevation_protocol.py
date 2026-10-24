"""Wire format between the unelevated process and the one-shot elevated helper.

The helper is started with an argument array (never a shell string) of exactly this shape:

    <recipe-id> --pid N --create-time ISO8601 --session N --result <path.json>

and writes one JSON document to the result file. Everything is typed and allowlisted on
both sides: an unknown recipe or a malformed argument is a rejection, not an attempt.
"""

import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from windows_medic.domain.models.elevation import (
    ElevatedOutcome,
    ElevatedRecipe,
    ElevatedRejection,
    ElevatedRequest,
    ElevatedResult,
)
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.repair import TerminationAttempt, TerminationOutcome

RESULT_SUFFIX = ".json"
_OPTIONS = ("--pid", "--create-time", "--session", "--result")


def encode_request(request: ElevatedRequest, result_path: Path) -> list[str]:
    """The helper's argument array for *request*; the result lands in *result_path*."""
    return [
        request.recipe.value,
        "--pid",
        str(request.target.pid),
        "--create-time",
        request.target.create_time.isoformat(),
        "--session",
        str(request.session),
        "--result",
        str(result_path),
    ]


def result_path_of(argv: Sequence[str]) -> Path | None:
    """Best-effort extraction of ``--result`` so even a rejection can be reported back."""
    tokens = list(argv)
    if "--result" not in tokens:
        return None
    index = tokens.index("--result")
    if index + 1 >= len(tokens):
        return None
    path = Path(tokens[index + 1])
    return path if path.is_absolute() and path.suffix == RESULT_SUFFIX else None


def parse_request(argv: Sequence[str]) -> tuple[ElevatedRequest, Path] | ElevatedRejection:
    """Strictly parse the helper's arguments; anything unexpected is a rejection."""
    tokens = list(argv)
    if not tokens:
        return ElevatedRejection.MALFORMED_ARGUMENTS
    recipe = next((r for r in ElevatedRecipe if r.value == tokens[0]), None)
    if recipe is None:
        return ElevatedRejection.UNKNOWN_RECIPE
    rest = tokens[1:]
    if len(rest) != 2 * len(_OPTIONS):
        return ElevatedRejection.MALFORMED_ARGUMENTS
    values = dict(zip(rest[0::2], rest[1::2], strict=True))
    if set(values) != set(_OPTIONS):
        return ElevatedRejection.MALFORMED_ARGUMENTS
    parsed = _typed_values(values)
    if parsed is None:
        return ElevatedRejection.MALFORMED_ARGUMENTS
    identity, session, result_path = parsed
    return ElevatedRequest(recipe, identity, session), result_path


def _typed_values(values: dict[str, str]) -> tuple[ProcessIdentity, int, Path] | None:
    try:
        pid = int(values["--pid"])
        session = int(values["--session"])
        create_time = datetime.fromisoformat(values["--create-time"])
    except ValueError:
        return None
    if create_time.tzinfo is None or pid < 0 or session < 0:
        return None
    result_path = Path(values["--result"])
    if not result_path.is_absolute() or result_path.suffix != RESULT_SUFFIX:
        return None
    return ProcessIdentity(pid, create_time), session, result_path


def encode_result(result: ElevatedResult) -> str:
    termination = (
        None
        if result.termination is None
        else {"outcome": result.termination.outcome.value, "detail": result.termination.detail}
    )
    return json.dumps(
        {
            "outcome": result.outcome.value,
            "termination": termination,
            "rejection": None if result.rejection is None else result.rejection.value,
            "detail": result.detail,
        }
    )


def decode_result(text: str) -> ElevatedResult | None:
    """The helper's result, or ``None`` when the document is not one."""
    try:
        document = json.loads(text)
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None
    try:
        outcome = ElevatedOutcome(str(document["outcome"]))
        raw_rejection = document.get("rejection")
        rejection = None if raw_rejection is None else ElevatedRejection(str(raw_rejection))
        detail = document.get("detail")
        raw_termination = document.get("termination")
        termination = (
            None
            if raw_termination is None
            else TerminationAttempt(
                TerminationOutcome(str(raw_termination["outcome"])),
                None if raw_termination.get("detail") is None else str(raw_termination["detail"]),
            )
        )
    except (KeyError, TypeError, ValueError):
        return None
    return ElevatedResult(
        outcome=outcome,
        termination=termination,
        rejection=rejection,
        detail=None if detail is None else str(detail),
    )
