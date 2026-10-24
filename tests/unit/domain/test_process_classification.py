"""Development-process classifier: names and command-line/path markers, reported explicitly."""

from dataclasses import replace

from tests.builders import NOT_SUPPORTED, process
from windows_medic.domain.policies.process_classification import (
    DevelopmentClassifier,
    classify_development,
)

CLASSIFIER = DevelopmentClassifier(
    process_names=("node.exe", "python.exe", "esbuild.exe"),
    command_markers=("npm", "npx", "vite", "ms-playwright", "pytest"),
)


def test_executable_name_match_is_reported_as_the_name() -> None:
    match = classify_development(process(10, name="Node.exe"), CLASSIFIER)

    assert match is not None
    assert match.matched_name == "node.exe"
    assert match.matched_markers == ()


def test_command_line_markers_are_reported_even_for_unlisted_names() -> None:
    observation = replace(
        process(11, name="node.exe"),
        exe_path="C:\\Program Files\\nodejs\\node.exe",
        command_line=(
            "C:\\Program Files\\nodejs\\node.exe",
            "C:\\Users\\dev\\AppData\\Roaming\\npm\\node_modules\\vite\\bin\\vite.js",
            "--port",
            "5173",
        ),
    )

    match = classify_development(observation, CLASSIFIER)

    assert match is not None
    assert match.matched_name == "node.exe"
    assert match.matched_markers == ("npm", "vite")


def test_executable_path_markers_classify_browsers_installed_by_playwright() -> None:
    observation = replace(
        process(12, name="chrome.exe"),
        exe_path="C:\\Users\\dev\\AppData\\Local\\ms-playwright\\chromium-1181\\chrome-win\\chrome.exe",
        command_line=NOT_SUPPORTED,
    )

    match = classify_development(observation, CLASSIFIER)

    assert match is not None
    assert match.matched_name is None
    assert match.matched_markers == ("ms-playwright",)


def test_markers_match_component_prefixes_not_substrings() -> None:
    observation = replace(
        process(13, name="editor.exe"),
        exe_path="C:\\tools\\my-npm-notes\\editor.exe",
        command_line=("editor.exe", "notes-about-vite.txt"),
    )

    assert classify_development(observation, CLASSIFIER) is None


def test_unavailable_fields_do_not_prevent_a_match_on_what_is_known() -> None:
    observation = replace(
        process(14, name=NOT_SUPPORTED), exe_path=NOT_SUPPORTED, command_line=("pytest", "-q")
    )

    match = classify_development(observation, CLASSIFIER)

    assert match is not None
    assert match.matched_name is None
    assert match.matched_markers == ("pytest",)


def test_nothing_known_means_no_classification() -> None:
    observation = replace(
        process(15, name=NOT_SUPPORTED), exe_path=NOT_SUPPORTED, command_line=NOT_SUPPORTED
    )

    assert classify_development(observation, CLASSIFIER) is None
