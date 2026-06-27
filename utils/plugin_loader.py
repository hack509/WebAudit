"""
Plugin Loader — discovers external WebAudit audit modules via entry_points.

Third-party packages can register custom auditors by declaring in their
pyproject.toml:

    [project.entry-points."webaudit.auditors"]
    my_module = "my_package.auditors:MyAuditor"

The plugin class must:
  - Inherit from `audit.base.BaseAuditor`
  - Define MODULE_NAME and MODULE_DESCRIPTION class attributes
  - Implement `async def run(self) -> AuditResult`

Usage in AuditRunner:
    from utils.plugin_loader import load_plugins
    plugins = load_plugins()           # {name: AuditorClass}
    for name, cls in plugins.items():
        runner.register_auditor(cls(config))
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Type

from utils.logger import get_logger

if TYPE_CHECKING:
    from audit.base import BaseAuditor

logger = get_logger("plugin_loader")

_ENTRY_POINT_GROUP = "webaudit.auditors"


def load_plugins() -> dict[str, Type["BaseAuditor"]]:
    """Return a dict of {module_name: AuditorClass} from installed plugins."""
    plugins: dict[str, Type["BaseAuditor"]] = {}

    try:
        eps = entry_points(group=_ENTRY_POINT_GROUP)
    except Exception as e:
        logger.warning(f"Could not load entry_points for '{_ENTRY_POINT_GROUP}': {e}")
        return plugins

    for ep in eps:
        try:
            cls = ep.load()
            name = getattr(cls, "MODULE_NAME", ep.name)
            plugins[name] = cls
            logger.info(f"Loaded plugin: {name} ({ep.value})")
        except Exception as e:
            logger.error(f"Failed to load plugin '{ep.name}': {e}")

    if plugins:
        logger.info(f"{len(plugins)} external plugin(s) loaded: {list(plugins)}")

    return plugins
