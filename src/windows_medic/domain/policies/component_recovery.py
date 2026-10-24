"""Explorer/DWM recovery: instance selection, replacement detection, recipe classification.

Both components run one instance per interactive session. The instance to restart is the
*oldest* one with the component's image name in the caller's session (the shell / the
session compositor; newer instances are separate-process folder windows). A replacement
is a new identity with the same image name in the same session created after the plan.
DWM is high risk and may only be terminated through the elevated helper; nothing here or
elsewhere ever launches a ``dwm.exe`` of its own.
"""

from dataclasses import dataclass
from datetime import datetime

from windows_medic.domain.models.component import WindowsComponent
from windows_medic.domain.models.metric import available
from windows_medic.domain.models.process import ProcessIdentity, ProcessObservation
from windows_medic.domain.models.repair import RepairAction, RiskLevel
from windows_medic.domain.models.samples import ProcessSnapshot


@dataclass(frozen=True, slots=True)
class ComponentRecipe:
    action: RepairAction
    risk: RiskLevel
    requires_elevation: bool
    may_start: bool


_RECIPES = {
    WindowsComponent.EXPLORER: ComponentRecipe(
        action=RepairAction.WINDOWS_EXPLORER_RESTART,
        risk=RiskLevel.MEDIUM,
        requires_elevation=False,
        may_start=True,
    ),
    WindowsComponent.DWM: ComponentRecipe(
        action=RepairAction.WINDOWS_DWM_RESTART,
        risk=RiskLevel.HIGH,
        requires_elevation=True,
        may_start=False,
    ),
}


def component_recipe(component: WindowsComponent) -> ComponentRecipe:
    return _RECIPES[component]


def session_of(snapshot: ProcessSnapshot, pid: int) -> int | None:
    """The session of *pid* as observed in *snapshot*; ``None`` when not knowable."""
    own = next((o for o in snapshot.processes if o.identity.pid == pid), None)
    if own is None or not available(own.session_id):
        return None
    return own.session_id


def select_component_instance(
    snapshot: ProcessSnapshot, component: WindowsComponent, *, session: int
) -> ProcessObservation | None:
    """The oldest instance of *component* in *session*, or ``None``."""
    candidates = _instances(snapshot, component, session)
    return min(candidates, key=lambda o: (o.identity.create_time, o.identity.pid), default=None)


def replacement_instance(
    snapshot: ProcessSnapshot,
    component: WindowsComponent,
    *,
    session: int,
    old: ProcessIdentity,
    since: datetime,
) -> ProcessObservation | None:
    """A fresh instance of *component* in *session* created at or after *since*."""
    candidates = [
        o
        for o in _instances(snapshot, component, session)
        if o.identity != old and o.identity.create_time >= since
    ]
    return min(candidates, key=lambda o: (o.identity.create_time, o.identity.pid), default=None)


def _instances(
    snapshot: ProcessSnapshot, component: WindowsComponent, session: int
) -> list[ProcessObservation]:
    return [
        o
        for o in snapshot.processes
        if available(o.name)
        and o.name.lower() == component.image_name
        and available(o.session_id)
        and o.session_id == session
    ]
