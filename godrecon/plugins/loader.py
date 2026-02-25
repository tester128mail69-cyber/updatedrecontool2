"""Plugin loader for GODRECON.

Scans a configurable plugin directory (``~/.godrecon/plugins/`` by default)
for ``.py`` files that define a class inheriting from
:class:`~godrecon.modules.base.BaseModule`, then registers each discovered
class in the shared :data:`godrecon.plugins._REGISTRY`.

Usage::

    from godrecon.core.config import load_config
    from godrecon.plugins.loader import load_plugins

    cfg = load_config()
    registry = load_plugins(cfg)
    # registry == {"my_plugin": <class MyPlugin>}
"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Type

from godrecon.utils.logger import get_logger

if TYPE_CHECKING:
    from godrecon.core.config import Config

logger = get_logger(__name__)


def load_plugins(config: "Config") -> Dict[str, Type]:
    """Discover and register plugins from the configured plugin directory.

    Scans ``config.plugins.plugin_dir`` for ``.py`` files.  Each file is
    imported and inspected; any class that is a non-abstract subclass of
    :class:`~godrecon.modules.base.BaseModule` is added to
    :data:`godrecon.plugins._REGISTRY` under its ``name`` attribute (or the
    class name as a fallback).

    All errors are caught and logged so that a broken plugin never prevents
    the application from starting.

    Args:
        config: Global scan configuration.

    Returns:
        The populated registry dict mapping plugin name to plugin class.
    """
    import godrecon.plugins as plugins_pkg
    from godrecon.modules.base import BaseModule

    if not config.plugins.enabled:
        logger.debug("Plugin loading is disabled in configuration.")
        return plugins_pkg._REGISTRY

    plugin_dir = Path(config.plugins.plugin_dir).expanduser()

    if not plugin_dir.exists():
        logger.debug(
            "Plugin directory '%s' does not exist — skipping plugin load.",
            plugin_dir,
        )
        return plugins_pkg._REGISTRY

    if not plugin_dir.is_dir():
        logger.warning(
            "Plugin path '%s' is not a directory — skipping plugin load.",
            plugin_dir,
        )
        return plugins_pkg._REGISTRY

    logger.debug("Loading plugins from '%s'.", plugin_dir)
    for py_file in sorted(plugin_dir.glob("*.py")):
        _load_plugin_file(py_file, BaseModule, plugins_pkg._REGISTRY)

    return plugins_pkg._REGISTRY


def _load_plugin_file(
    py_file: Path,
    base_class: Type,
    registry: Dict[str, Type],
) -> None:
    """Import a single plugin file and register its ``BaseModule`` subclasses.

    Args:
        py_file: Path to the ``.py`` plugin file.
        base_class: The base class that plugins must inherit from.
        registry: The registry dict to populate.
    """
    module_name = f"godrecon_plugin_{py_file.stem}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        if spec is None or spec.loader is None:
            logger.warning(
                "Could not create import spec for plugin file '%s' — skipping.",
                py_file.name,
            )
            return

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]

        registered = 0
        for _attr_name, attr in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(attr, base_class)
                and attr is not base_class
                and not inspect.isabstract(attr)
                and attr.__module__ == module_name
            ):
                if not hasattr(attr, "name") or attr.name == "base":
                    logger.warning(
                        "Plugin class '%s' in '%s' has no unique 'name' attribute"
                        " — using class name as fallback.",
                        _attr_name,
                        py_file.name,
                    )
                plugin_name = getattr(attr, "name", _attr_name)
                if plugin_name == "base":
                    plugin_name = _attr_name
                registry[plugin_name] = attr
                registered += 1
                logger.info(
                    "Registered plugin '%s' from '%s'.",
                    plugin_name,
                    py_file.name,
                )

        if registered == 0:
            logger.debug(
                "No BaseModule subclasses found in plugin file '%s'.",
                py_file.name,
            )

    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Failed to load plugin file '%s': %s",
            py_file.name,
            exc,
        )
