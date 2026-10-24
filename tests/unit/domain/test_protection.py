"""Centralized protection policy: critical Windows processes, self, user additions, components."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.builders import process
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.policies.protection import (
    DEFAULT_CRITICAL_PROCESS_NAMES,
    DEFAULT_WINDOWS_COMPONENT_NAMES,
    ProtectionLevel,
    ProtectionPolicy,
    ProtectionReason,
    ProtectionVerdict,
    classify_protection,
)

POLICY = ProtectionPolicy(
    own_pid=4242,
    windows_medic_markers=("windows-medic", "windows_medic"),
    user_protected_names=("backup-agent.exe",),
    windows_directory="C:\\Windows",
)


def observed(
    pid: int = 1000,
    name: str = "app.exe",
    exe_path: str | Unavailable | None = None,
    command_line: tuple[str, ...] | Unavailable | None = None,
) -> ProcessObservation:
    base = process(pid, name=name)
    return ProcessObservation(
        **{
            **{slot: getattr(base, slot) for slot in base.__slots__},
            "exe_path": f"C:\\Apps\\{name}" if exe_path is None else exe_path,
            "command_line": (name,) if command_line is None else command_line,
        }
    )


def verdict(observation: ProcessObservation) -> ProtectionVerdict:
    return classify_protection(observation, POLICY)


class TestCriticalWindowsProcesses:
    @pytest.mark.parametrize(
        "name",
        [
            "System",
            "Registry",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
            "Memory Compression",
            "Secure System",
        ],
    )
    def test_spec_listed_processes_are_critical(self, name: str) -> None:
        result = verdict(observed(name=name, exe_path=f"C:\\Windows\\System32\\{name}"))

        assert result.level is ProtectionLevel.CRITICAL
        assert ProtectionReason.CRITICAL_WINDOWS_PROCESS in result.reasons

    def test_matching_is_case_insensitive(self) -> None:
        assert verdict(observed(name="LSASS.EXE")).level is ProtectionLevel.CRITICAL

    def test_critical_name_is_protected_even_when_its_path_cannot_be_read(self) -> None:
        denied = Unavailable(UnavailableReason.ACCESS_DENIED)

        result = verdict(observed(name="csrss.exe", exe_path=denied))

        assert result.level is ProtectionLevel.CRITICAL

    def test_critical_name_outside_the_windows_directory_is_still_critical(self) -> None:
        # Defence in depth: a look-alike is suspicious, but the policy never *lowers*
        # protection because of an unexpected path.
        result = verdict(observed(name="lsass.exe", exe_path="C:\\Temp\\lsass.exe"))

        assert result.level is ProtectionLevel.CRITICAL

    def test_default_list_covers_the_product_spec_minimum(self) -> None:
        assert {
            "system",
            "registry",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
        } <= set(DEFAULT_CRITICAL_PROCESS_NAMES)


class TestSelfProtection:
    def test_own_process_is_protected_by_identity(self) -> None:
        result = verdict(observed(pid=4242, name="python.exe"))

        assert result.level is ProtectionLevel.PROTECTED
        assert result.reasons == (ProtectionReason.WINDOWS_MEDIC_SELF,)

    def test_other_windows_medic_processes_are_recognised_by_command_line(self) -> None:
        agent = observed(
            pid=77,
            name="python.exe",
            command_line=("C:\\venv\\Scripts\\python.exe", "-m", "windows_medic_agent.main"),
        )

        assert verdict(agent).level is ProtectionLevel.PROTECTED
        assert ProtectionReason.WINDOWS_MEDIC_SELF in verdict(agent).reasons

    def test_windows_medic_console_script_is_recognised_by_executable(self) -> None:
        mcp = observed(
            pid=78,
            name="windows-medic-mcp.exe",
            exe_path="C:\\venv\\Scripts\\windows-medic-mcp.exe",
        )

        assert verdict(mcp).level is ProtectionLevel.PROTECTED

    def test_marker_matching_is_a_whole_token_not_a_substring_of_unrelated_paths(self) -> None:
        unrelated = observed(
            name="node.exe", command_line=("node", "C:\\src\\my-windows-medic-notes\\app.js")
        )

        assert verdict(unrelated).level is ProtectionLevel.NONE

    def test_a_process_merely_running_inside_a_windows_medic_checkout_is_not_self(self) -> None:
        # `git clone .../windows-medic` names the folder exactly like the marker.
        dev_server = observed(
            name="python.exe",
            exe_path="C:\\Python313\\python.exe",
            command_line=(
                "C:\\Python313\\python.exe",
                "C:\\src\\windows-medic\\tests\\integration\\windows\\process_tree_child.py",
            ),
        )
        node = observed(
            name="node.exe",
            exe_path="C:\\src\\windows-medic\\tools\\node.exe",
            command_line=("node", "C:\\src\\windows_medic_fork\\server.js"),
        )

        assert verdict(dev_server).level is ProtectionLevel.NONE
        assert verdict(node).level is ProtectionLevel.NONE

    @pytest.mark.parametrize(
        "command_line",
        [
            # what the logon task's launcher spawns: the interpreter running the script
            (
                "C:\\src\\windows-medic\\.venv\\Scripts\\python.exe",
                "C:\\src\\windows-medic\\.venv\\Scripts\\windows-medic-agentw.exe",
                "--log-file",
                "C:\\Users\\dev\\AppData\\Local\\WindowsMedic\\logs\\windows-medic-agent.log",
            ),
            ("uv", "run", "--directory", "C:\\src\\medic", "windows-medic-mcp"),
            ("python", "-m", "windows_medic_cli", "health"),
        ],
    )
    def test_windows_medic_entry_points_are_self_whatever_folder_they_live_in(
        self, command_line: tuple[str, ...]
    ) -> None:
        launched = observed(
            name="python.exe", exe_path="C:\\Python313\\python.exe", command_line=command_line
        )

        assert ProtectionReason.WINDOWS_MEDIC_SELF in verdict(launched).reasons


class TestUserAdditions:
    def test_configured_names_are_protected(self) -> None:
        result = verdict(observed(name="backup-agent.exe"))

        assert result.level is ProtectionLevel.PROTECTED
        assert result.reasons == (ProtectionReason.USER_CONFIGURED,)

    def test_user_addition_matching_is_case_insensitive(self) -> None:
        assert verdict(observed(name="Backup-Agent.EXE")).level is ProtectionLevel.PROTECTED


class TestWindowsComponents:
    @pytest.mark.parametrize("name", ["explorer.exe", "dwm.exe", "svchost.exe", "taskhostw.exe"])
    def test_known_component_names_are_components(self, name: str) -> None:
        result = verdict(observed(name=name, exe_path=f"C:\\Windows\\System32\\{name}"))

        assert result.level is ProtectionLevel.WINDOWS_COMPONENT
        assert ProtectionReason.WINDOWS_COMPONENT_NAME in result.reasons

    def test_anything_running_from_the_windows_directory_is_a_component(self) -> None:
        result = verdict(
            observed(name="oddball.exe", exe_path="C:\\Windows\\System32\\oddball.exe")
        )

        assert result.level is ProtectionLevel.WINDOWS_COMPONENT
        assert result.reasons == (ProtectionReason.WINDOWS_DIRECTORY,)

    def test_windows_directory_match_is_case_insensitive_and_prefix_safe(self) -> None:
        assert (
            verdict(observed(exe_path="c:\\windows\\explorer.exe")).level
            is ProtectionLevel.WINDOWS_COMPONENT
        )
        assert verdict(observed(exe_path="C:\\WindowsApps\\x.exe")).level is ProtectionLevel.NONE

    def test_component_name_outside_the_windows_directory_is_still_marked(self) -> None:
        result = verdict(observed(name="svchost.exe", exe_path="C:\\Temp\\svchost.exe"))

        assert result.level is ProtectionLevel.WINDOWS_COMPONENT
        assert result.reasons == (ProtectionReason.WINDOWS_COMPONENT_NAME,)

    def test_default_component_list_includes_the_shell_and_compositor(self) -> None:
        assert {"explorer.exe", "dwm.exe"} <= set(DEFAULT_WINDOWS_COMPONENT_NAMES)


class TestPrecedence:
    def test_levels_are_ordered(self) -> None:
        assert (
            ProtectionLevel.NONE
            < ProtectionLevel.WINDOWS_COMPONENT
            < ProtectionLevel.PROTECTED
            < ProtectionLevel.CRITICAL
        )

    def test_all_comparison_operators_follow_the_rank(self) -> None:
        assert ProtectionLevel.CRITICAL > ProtectionLevel.PROTECTED
        assert ProtectionLevel.PROTECTED >= ProtectionLevel.PROTECTED
        assert ProtectionLevel.NONE <= ProtectionLevel.WINDOWS_COMPONENT
        assert not ProtectionLevel.NONE > ProtectionLevel.CRITICAL
        assert ProtectionLevel.NONE.__lt__("none") is NotImplemented

    def test_highest_level_wins_and_all_reasons_are_kept(self) -> None:
        # Our own process is also a user-protected name and lives in the Windows directory.
        policy = ProtectionPolicy(
            own_pid=1,
            windows_medic_markers=(),
            user_protected_names=("python.exe",),
            windows_directory="C:\\Windows",
        )
        result = classify_protection(
            observed(pid=1, name="python.exe", exe_path="C:\\Windows\\python.exe"), policy
        )

        assert result.level is ProtectionLevel.PROTECTED
        assert set(result.reasons) == {
            ProtectionReason.WINDOWS_MEDIC_SELF,
            ProtectionReason.USER_CONFIGURED,
            ProtectionReason.WINDOWS_DIRECTORY,
        }

    def test_ordinary_process_has_no_protection_and_no_reasons(self) -> None:
        assert verdict(observed(name="node.exe")) == ProtectionVerdict(ProtectionLevel.NONE, ())

    def test_unavailable_name_and_path_yield_no_protection_but_never_crash(self) -> None:
        denied = Unavailable(UnavailableReason.ACCESS_DENIED)
        anonymous = ProcessObservation(
            **{
                **{slot: getattr(observed(), slot) for slot in observed().__slots__},
                "name": denied,
                "exe_path": denied,
                "command_line": denied,
            }
        )

        assert verdict(anonymous).level is ProtectionLevel.NONE

    @given(name=st.text(min_size=1, max_size=40), pid=st.integers(min_value=1, max_value=99999))
    def test_classification_is_total_and_deterministic(self, name: str, pid: int) -> None:
        observation = observed(pid=pid, name=name)

        first, second = verdict(observation), verdict(observation)

        assert first == second
        assert isinstance(first.level, ProtectionLevel)
