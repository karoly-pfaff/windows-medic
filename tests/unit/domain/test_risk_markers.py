"""Risk markers derived from ancestry and tree membership. Evidence, not verdicts."""

from datetime import datetime, timedelta

from tests.builders import BOOT, process, process_snapshot
from windows_medic.domain.models.process import ProcessObservation
from windows_medic.domain.models.tree import build_process_tree
from windows_medic.domain.policies.protection import ProtectionPolicy
from windows_medic.domain.policies.risk_markers import (
    AncestryPolicy,
    RiskMarker,
    assess_risk_markers,
)

PROTECTION = ProtectionPolicy(
    own_pid=4242,
    windows_medic_markers=("windows-medic", "windows_medic"),
    user_protected_names=(),
    windows_directory="C:\\Windows",
)
ANCESTRY = AncestryPolicy(
    claude_markers=("claude",),
    terminal_process_names=("windowsterminal.exe", "cmd.exe", "powershell.exe", "pwsh.exe"),
)


def at(seconds: int) -> datetime:
    return BOOT + timedelta(seconds=seconds)


def markers(target: ProcessObservation, *others: ProcessObservation) -> tuple[RiskMarker, ...]:
    tree = build_process_tree(process_snapshot(target, *others))
    return assess_risk_markers(
        target.identity, tree, protection=PROTECTION, ancestry=ANCESTRY, descendant_limit=100
    )


class TestClaudeAncestry:
    def test_direct_claude_parent(self) -> None:
        claude = process(1, created=BOOT, name="claude.exe")
        target = process(2, created=at(5), parent_pid=1)

        assert RiskMarker.CLAUDE_ANCESTRY in markers(target, claude)

    def test_claude_code_running_under_node_is_detected_by_its_command_line(self) -> None:
        node = process(1, created=BOOT, name="node.exe")
        node = ProcessObservation(
            **{
                **{slot: getattr(node, slot) for slot in node.__slots__},
                "command_line": (
                    "node",
                    "C:\\Users\\u\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js",
                ),
            }
        )
        shell = process(2, created=at(1), parent_pid=1, name="pwsh.exe")
        target = process(3, created=at(5), parent_pid=2)

        assert RiskMarker.CLAUDE_ANCESTRY in markers(target, node, shell)

    def test_claude_as_a_descendant_is_not_ancestry(self) -> None:
        target = process(1, created=BOOT)
        claude = process(2, created=at(5), parent_pid=1, name="claude.exe")

        assert RiskMarker.CLAUDE_ANCESTRY not in markers(target, claude)


class TestWindowsMedicAncestry:
    def test_spawned_by_our_own_process(self) -> None:
        me = process(4242, created=BOOT, name="python.exe")
        target = process(9, created=at(5), parent_pid=4242)

        assert RiskMarker.WINDOWS_MEDIC_ANCESTRY in markers(target, me)

    def test_spawned_by_another_windows_medic_process(self) -> None:
        mcp = process(7, created=BOOT, name="windows-medic-mcp.exe")
        target = process(9, created=at(5), parent_pid=7)

        assert RiskMarker.WINDOWS_MEDIC_ANCESTRY in markers(target, mcp)


class TestTerminalAncestry:
    def test_interactive_terminal_ancestor(self) -> None:
        terminal = process(1, created=BOOT, name="WindowsTerminal.exe")
        shell = process(2, created=at(1), parent_pid=1, name="pwsh.exe")
        target = process(3, created=at(5), parent_pid=2)

        assert RiskMarker.TERMINAL_ANCESTRY in markers(target, terminal, shell)

    def test_service_host_ancestry_is_not_a_terminal(self) -> None:
        services = process(1, created=BOOT, name="services.exe")
        target = process(3, created=at(5), parent_pid=1)

        assert RiskMarker.TERMINAL_ANCESTRY not in markers(target, services)


class TestParentEvidence:
    def test_unresolved_parent_is_marked(self) -> None:
        target = process(3, created=at(5), parent_pid=999)

        assert RiskMarker.UNRESOLVED_PARENT in markers(target)

    def test_reused_parent_pid_is_marked_and_not_treated_as_ancestry(self) -> None:
        target = process(3, created=BOOT, parent_pid=1)
        impostor = process(1, created=at(5), name="claude.exe")

        result = markers(target, impostor)

        assert RiskMarker.UNRESOLVED_PARENT in result
        assert RiskMarker.CLAUDE_ANCESTRY not in result


class TestProtectedDescendants:
    def test_critical_descendant_is_marked(self) -> None:
        target = process(1, created=BOOT)
        child = process(2, created=at(1), parent_pid=1)
        critical = process(3, created=at(2), parent_pid=2, name="lsass.exe")

        assert RiskMarker.PROTECTED_DESCENDANT in markers(target, child, critical)

    def test_windows_component_descendant_is_not_protected_enough_to_mark(self) -> None:
        target = process(1, created=BOOT)
        component = process(2, created=at(1), parent_pid=1, name="conhost.exe")

        assert RiskMarker.PROTECTED_DESCENDANT not in markers(target, component)

    def test_our_own_process_as_descendant_is_marked(self) -> None:
        target = process(1, created=BOOT)
        me = process(4242, created=at(1), parent_pid=1)

        assert RiskMarker.PROTECTED_DESCENDANT in markers(target, me)


class TestShape:
    def test_ordinary_process_has_no_markers(self) -> None:
        parent = process(1, created=BOOT, name="explorer.exe")
        target = process(2, created=at(5), parent_pid=1, name="node.exe")

        assert markers(target, parent) == ()

    def test_markers_are_unique_and_in_declaration_order(self) -> None:
        claude = process(1, created=BOOT, name="claude.exe")
        terminal = process(2, created=at(1), parent_pid=1, name="cmd.exe")
        target = process(3, created=at(5), parent_pid=2)
        critical = process(4, created=at(6), parent_pid=3, name="csrss.exe")

        result = markers(target, claude, terminal, critical)

        assert result == (
            RiskMarker.CLAUDE_ANCESTRY,
            RiskMarker.TERMINAL_ANCESTRY,
            RiskMarker.PROTECTED_DESCENDANT,
        )
