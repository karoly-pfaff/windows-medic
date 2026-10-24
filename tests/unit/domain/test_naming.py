"""Name/path matching helpers shared by protection and risk policies."""

from dataclasses import replace

from tests.builders import process
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.policies.naming import (
    basename,
    candidate_names,
    mentions_marker,
    names_start_with_marker,
    under_directory,
)


def test_basename_handles_both_separators_and_empty_paths() -> None:
    assert basename("C:/Windows\\System32/svchost.exe") == "svchost.exe"
    assert basename("") == ""


def test_candidate_names_uses_whatever_is_available() -> None:
    denied = Unavailable(UnavailableReason.ACCESS_DENIED)
    observation = ProcessObservation(
        **{
            **{slot: getattr(process(1, name="App.EXE"), slot) for slot in process(1).__slots__},
            "exe_path": denied,
        }
    )

    assert candidate_names(observation) == frozenset({"app.exe"})


def test_no_markers_never_match() -> None:
    assert mentions_marker(process(1, name="windows-medic.exe"), ()) is False
    assert names_start_with_marker(process(1, name="windows-medic.exe"), ()) is False


def test_names_ignore_folders_but_not_file_names() -> None:
    in_checkout = replace(process(1), exe_path="C:\\src\\windows-medic\\bin\\tool.exe")
    script = replace(process(2), exe_path="C:\\venv\\Scripts\\Windows-Medic-MCP.exe")

    assert mentions_marker(in_checkout, ("windows-medic",)) is True
    assert names_start_with_marker(in_checkout, ("windows-medic",)) is False
    assert names_start_with_marker(script, ("windows-medic",)) is True


def test_under_directory_requires_a_directory_and_is_separator_aware() -> None:
    assert under_directory("C:\\Windows\\x.exe", "") is False
    assert under_directory("c:/windows/x.exe", "C:\\Windows") is True
    assert under_directory("C:\\WindowsApps\\x.exe", "C:\\Windows\\") is False
