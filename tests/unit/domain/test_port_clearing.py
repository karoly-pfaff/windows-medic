"""Clear-port eligibility: a plan is offered only when every owner is safe to act on."""

import pytest

from tests.builders import identity
from windows_medic.domain.models.network import (
    AddressFamily,
    ListeningEndpoint,
    TransportProtocol,
)
from windows_medic.domain.policies.port_clearing import (
    ClearPortBlocker,
    ClearPortEligibility,
    assess_clear_port,
)
from windows_medic.domain.policies.protection import ProtectionLevel


def endpoint(port: int = 5173, pid: int | None = 100) -> ListeningEndpoint:
    return ListeningEndpoint(
        protocol=TransportProtocol.TCP,
        family=AddressFamily.IPV4,
        address="127.0.0.1",
        port=port,
        owner_pid=pid,
    )


class TestEndpoint:
    def test_port_must_be_in_range(self) -> None:
        with pytest.raises(ValueError, match="port"):
            endpoint(port=70000)
        with pytest.raises(ValueError, match="port"):
            endpoint(port=0)

    def test_owner_pid_may_be_unknown(self) -> None:
        assert endpoint(pid=None).owner_pid is None


class TestEligibility:
    def test_single_unprotected_owner_is_eligible(self) -> None:
        result = assess_clear_port(
            resolved_levels=((identity(100), ProtectionLevel.NONE),), unresolved_count=0
        )

        assert result == ClearPortEligibility(eligible=True, blockers=())

    @pytest.mark.parametrize(
        "level",
        [ProtectionLevel.WINDOWS_COMPONENT, ProtectionLevel.PROTECTED, ProtectionLevel.CRITICAL],
    )
    def test_any_protected_owner_blocks(self, level: ProtectionLevel) -> None:
        result = assess_clear_port(
            resolved_levels=((identity(100), ProtectionLevel.NONE), (identity(200), level)),
            unresolved_count=0,
        )

        assert result.eligible is False
        assert result.blockers == (ClearPortBlocker.OWNER_PROTECTED,)

    def test_unresolved_owner_blocks(self) -> None:
        result = assess_clear_port(
            resolved_levels=((identity(100), ProtectionLevel.NONE),), unresolved_count=1
        )

        assert result.eligible is False
        assert result.blockers == (ClearPortBlocker.OWNER_UNRESOLVED,)

    def test_nothing_listening_blocks(self) -> None:
        result = assess_clear_port(resolved_levels=(), unresolved_count=0)

        assert result.eligible is False
        assert result.blockers == (ClearPortBlocker.NO_OWNER,)

    def test_blockers_are_unique_and_ordered(self) -> None:
        result = assess_clear_port(
            resolved_levels=(
                (identity(1), ProtectionLevel.CRITICAL),
                (identity(2), ProtectionLevel.PROTECTED),
            ),
            unresolved_count=2,
        )

        assert result.blockers == (
            ClearPortBlocker.OWNER_PROTECTED,
            ClearPortBlocker.OWNER_UNRESOLVED,
        )
