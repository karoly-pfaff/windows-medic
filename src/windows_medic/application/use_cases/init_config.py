"""``windows-medic config init``: write the documented defaults for the user to edit."""

from collections.abc import Callable
from pathlib import Path

from windows_medic.application.operations import Locations
from windows_medic.application.ports.workspace import Workspace


class InitConfig:
    def __init__(
        self, *, workspace: Workspace, locations: Locations, render_config: Callable[[], str]
    ) -> None:
        self._workspace = workspace
        self._locations = locations
        self._render_config = render_config

    def execute(self, *, force: bool) -> Path:
        """Write the default configuration; refuses an existing file unless *force*."""
        self._workspace.ensure_directory(self._locations.data_dir)
        self._workspace.write_text(
            self._locations.config_file, self._render_config(), overwrite=force
        )
        return self._locations.config_file
