"""Tests for godrecon.plugins.loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from godrecon.core.config import Config, PluginsConfig
from godrecon.modules.base import BaseModule, ModuleResult
from godrecon.plugins.loader import _load_plugin_file, load_plugins


# ---------------------------------------------------------------------------
# PluginsConfig tests
# ---------------------------------------------------------------------------


def test_plugins_config_defaults():
    cfg = PluginsConfig()
    assert cfg.enabled is True
    assert cfg.plugin_dir == "~/.godrecon/plugins"


def test_config_has_plugins_field():
    cfg = Config()
    assert hasattr(cfg, "plugins")
    assert isinstance(cfg.plugins, PluginsConfig)
    assert cfg.plugins.enabled is True


# ---------------------------------------------------------------------------
# load_plugins — disabled
# ---------------------------------------------------------------------------


def test_load_plugins_disabled_returns_empty(tmp_path):
    """When plugins.enabled is False, load_plugins returns without loading."""
    cfg = Config(plugins=PluginsConfig(enabled=False, plugin_dir=str(tmp_path)))
    import godrecon.plugins as plugins_pkg
    plugins_pkg._REGISTRY.clear()

    result = load_plugins(cfg)
    assert result is plugins_pkg._REGISTRY
    assert result == {}


# ---------------------------------------------------------------------------
# load_plugins — missing / non-directory paths
# ---------------------------------------------------------------------------


def test_load_plugins_missing_dir_returns_empty(tmp_path):
    """load_plugins silently skips a non-existent plugin directory."""
    nonexistent = tmp_path / "no_such_dir"
    cfg = Config(plugins=PluginsConfig(enabled=True, plugin_dir=str(nonexistent)))
    import godrecon.plugins as plugins_pkg
    plugins_pkg._REGISTRY.clear()

    result = load_plugins(cfg)
    assert result == {}


def test_load_plugins_file_path_not_dir(tmp_path):
    """load_plugins warns and skips when plugin_dir points to a file."""
    a_file = tmp_path / "notadir.txt"
    a_file.write_text("hello")
    cfg = Config(plugins=PluginsConfig(enabled=True, plugin_dir=str(a_file)))
    import godrecon.plugins as plugins_pkg
    plugins_pkg._REGISTRY.clear()

    result = load_plugins(cfg)
    assert result == {}


# ---------------------------------------------------------------------------
# _load_plugin_file — valid plugin
# ---------------------------------------------------------------------------


def _write_valid_plugin(path: Path) -> Path:
    """Write a minimal valid plugin file and return its path."""
    plugin_code = textwrap.dedent(
        """\
        from godrecon.modules.base import BaseModule, ModuleResult

        class HelloPlugin(BaseModule):
            name = "hello_plugin"
            description = "A test plugin"
            category = "test"

            async def _execute(self, target, config):
                return ModuleResult(module_name=self.name, target=target)
        """
    )
    py_file = path / "hello_plugin.py"
    py_file.write_text(plugin_code)
    return py_file


def test_load_plugin_file_registers_class(tmp_path):
    py_file = _write_valid_plugin(tmp_path)
    registry: dict = {}
    _load_plugin_file(py_file, BaseModule, registry)

    assert "hello_plugin" in registry
    cls = registry["hello_plugin"]
    assert issubclass(cls, BaseModule)
    assert cls.name == "hello_plugin"


def test_load_plugins_discovers_file(tmp_path):
    _write_valid_plugin(tmp_path)
    cfg = Config(plugins=PluginsConfig(enabled=True, plugin_dir=str(tmp_path)))
    import godrecon.plugins as plugins_pkg
    plugins_pkg._REGISTRY.clear()

    result = load_plugins(cfg)
    assert "hello_plugin" in result


# ---------------------------------------------------------------------------
# _load_plugin_file — file with no BaseModule subclass
# ---------------------------------------------------------------------------


def test_load_plugin_file_no_subclass(tmp_path):
    """Files without a BaseModule subclass register nothing (no error)."""
    py_file = tmp_path / "empty_plugin.py"
    py_file.write_text("x = 42\n")
    registry: dict = {}
    _load_plugin_file(py_file, BaseModule, registry)
    assert registry == {}


# ---------------------------------------------------------------------------
# _load_plugin_file — broken plugin
# ---------------------------------------------------------------------------


def test_load_plugin_file_syntax_error_is_caught(tmp_path):
    """A plugin with a syntax error must not propagate an exception."""
    py_file = tmp_path / "bad_plugin.py"
    py_file.write_text("def broken(:\n")
    registry: dict = {}
    # Should not raise
    _load_plugin_file(py_file, BaseModule, registry)
    assert registry == {}


# ---------------------------------------------------------------------------
# Instantiation of a loaded plugin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_loaded_plugin_can_be_instantiated_and_run(tmp_path):
    """A plugin loaded from disk can be instantiated and run correctly."""
    _write_valid_plugin(tmp_path)
    cfg = Config(plugins=PluginsConfig(enabled=True, plugin_dir=str(tmp_path)))
    import godrecon.plugins as plugins_pkg
    plugins_pkg._REGISTRY.clear()

    registry = load_plugins(cfg)
    plugin_cls = registry["hello_plugin"]
    instance = plugin_cls()
    result = await instance.run("example.com", cfg)
    assert result.module_name == "hello_plugin"
    assert result.target == "example.com"
    assert result.error is None
