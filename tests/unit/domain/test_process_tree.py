"""ProcessTree: exact-identity ancestry; a reused parent PID is evidence, not an edge."""

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.builders import BOOT, identity, process, process_snapshot
from windows_medic.domain.models.metric import Unavailable, UnavailableReason
from windows_medic.domain.models.process import ProcessIdentity
from windows_medic.domain.models.tree import (
    MAX_ANCESTRY_DEPTH,
    AncestryEnd,
    ProcessTree,
    UnresolvedParent,
    UnresolvedParentReason,
    build_process_tree,
)

LATER = BOOT + timedelta(seconds=10)


def tree(*observations: object) -> ProcessTree:
    return build_process_tree(process_snapshot(*observations))  # type: ignore[arg-type]


class TestParentResolution:
    def test_links_child_to_the_parent_that_existed_before_it(self) -> None:
        parent = process(100, created=BOOT)
        child = process(200, created=LATER, parent_pid=100)

        assert tree(parent, child).parent_of(child.identity) == parent.identity

    def test_parent_pid_created_after_the_child_is_a_reused_pid_not_a_parent(self) -> None:
        child = process(200, created=BOOT, parent_pid=100)
        impostor = process(100, created=LATER)

        link = tree(child, impostor).parent_of(child.identity)

        assert link == UnresolvedParent(100, UnresolvedParentReason.PARENT_PID_REUSED)
        assert tree(child, impostor).children_of(impostor.identity) == ()

    def test_missing_parent_pid_is_recorded_as_gone(self) -> None:
        orphan = process(200, created=LATER, parent_pid=100)

        assert tree(orphan).parent_of(orphan.identity) == UnresolvedParent(
            100, UnresolvedParentReason.PARENT_GONE
        )

    def test_unavailable_parent_pid_is_recorded_as_unknown(self) -> None:
        denied = process(200, parent_pid=Unavailable(UnavailableReason.ACCESS_DENIED))

        assert tree(denied).parent_of(denied.identity) == UnresolvedParent(
            None, UnresolvedParentReason.PARENT_UNKNOWN
        )

    def test_process_claiming_itself_as_parent_is_corrupt_not_a_cycle(self) -> None:
        loop = process(7, parent_pid=7)

        assert tree(loop).parent_of(loop.identity) == UnresolvedParent(
            7, UnresolvedParentReason.INVALID
        )

    def test_parent_with_identical_create_time_is_accepted(self) -> None:
        parent = process(1, created=BOOT)
        child = process(2, created=BOOT, parent_pid=1)

        assert tree(parent, child).parent_of(child.identity) == parent.identity

    def test_unknown_identity_is_a_programming_error(self) -> None:
        with pytest.raises(KeyError):
            tree().parent_of(identity(1))


class TestNavigation:
    def test_children_are_ordered_by_identity(self) -> None:
        parent = process(1, created=BOOT)
        kids = [process(pid, created=LATER, parent_pid=1) for pid in (30, 10, 20)]

        assert [c.pid for c in tree(parent, *kids).children_of(parent.identity)] == [10, 20, 30]

    def test_ancestors_are_nearest_first_up_to_the_root(self) -> None:
        grand = process(1, created=BOOT)
        parent = process(2, created=BOOT + timedelta(seconds=1), parent_pid=1)
        child = process(3, created=LATER, parent_pid=2)

        ancestry = tree(grand, parent, child).ancestry_of(child.identity)

        assert ancestry.ancestors == (parent.identity, grand.identity)
        assert ancestry.end is AncestryEnd.UNRESOLVED
        assert ancestry.top_link == UnresolvedParent(4, UnresolvedParentReason.PARENT_GONE)

    def test_ancestry_stops_at_an_unresolved_parent(self) -> None:
        child = process(3, created=LATER, parent_pid=999)

        ancestry = tree(child).ancestry_of(child.identity)

        assert ancestry.ancestors == ()
        assert ancestry.end is AncestryEnd.UNRESOLVED
        assert ancestry.top_link == UnresolvedParent(999, UnresolvedParentReason.PARENT_GONE)

    def test_descendants_are_breadth_first_with_depth(self) -> None:
        root = process(1, created=BOOT)
        a = process(2, created=BOOT + timedelta(seconds=1), parent_pid=1)
        b = process(3, created=BOOT + timedelta(seconds=1), parent_pid=1)
        aa = process(4, created=LATER, parent_pid=2)

        descendants = tree(root, a, b, aa).descendants_of(root.identity)

        assert [(d.identity.pid, d.depth) for d in descendants] == [(2, 1), (3, 1), (4, 2)]

    def test_descendants_are_bounded(self) -> None:
        root = process(1, created=BOOT)
        kids = [process(pid, created=LATER, parent_pid=1) for pid in range(2, 12)]

        assert len(tree(root, *kids).descendants_of(root.identity, limit=3)) == 3

    def test_observation_lookup(self) -> None:
        only = process(5)

        assert tree(only).observation(only.identity) is only
        assert tree(only).contains(only.identity)
        assert not tree(only).contains(identity(5, LATER))

    def test_roots_are_processes_without_a_resolved_parent(self) -> None:
        root = process(1, created=BOOT, parent_pid=999)
        child = process(2, created=LATER, parent_pid=1)

        assert tree(root, child).roots() == (root.identity,)


class TestCorruptData:
    def test_two_node_cycle_with_equal_create_times_terminates(self) -> None:
        a = process(1, created=BOOT, parent_pid=2)
        b = process(2, created=BOOT, parent_pid=1)

        ancestry = tree(a, b).ancestry_of(a.identity)

        assert ancestry.ancestors == (b.identity,)
        assert ancestry.end is AncestryEnd.CYCLE
        assert ancestry.top_link is None

    def test_descendants_of_a_cycle_terminate(self) -> None:
        a = process(1, created=BOOT, parent_pid=2)
        b = process(2, created=BOOT, parent_pid=1)

        descendants = tree(a, b).descendants_of(a.identity)

        assert [d.identity.pid for d in descendants] == [2]

    def test_ancestry_depth_is_bounded(self) -> None:
        chain = [process(1, created=BOOT)]
        for pid in range(2, MAX_ANCESTRY_DEPTH + 10):
            created = BOOT + timedelta(microseconds=pid)
            chain.append(process(pid, created=created, parent_pid=pid - 1))

        ancestry = tree(*chain).ancestry_of(chain[-1].identity)

        assert len(ancestry.ancestors) == MAX_ANCESTRY_DEPTH
        assert ancestry.end is AncestryEnd.DEPTH_LIMIT

    def test_duplicate_identities_in_a_snapshot_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="duplicate"):
            tree(process(1), process(1))

    @given(
        parents=st.lists(st.integers(min_value=0, max_value=12), min_size=1, max_size=12),
    )
    def test_any_parent_wiring_terminates_and_never_links_a_later_parent(
        self, parents: list[int]
    ) -> None:
        observations = [
            process(pid + 1, created=BOOT + timedelta(seconds=pid), parent_pid=parent)
            for pid, parent in enumerate(parents)
        ]
        built = tree(*observations)

        for observation in observations:
            ancestry = built.ancestry_of(observation.identity)
            assert len(ancestry.ancestors) <= MAX_ANCESTRY_DEPTH
            link = built.parent_of(observation.identity)
            if isinstance(link, ProcessIdentity):
                assert link.create_time <= observation.identity.create_time
                assert link != observation.identity
            built.descendants_of(observation.identity)
