"""Tests for godrecon.core.checkpoint."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from godrecon.core.checkpoint import load_checkpoint, save_checkpoint


# ---------------------------------------------------------------------------
# save_checkpoint tests
# ---------------------------------------------------------------------------


def test_save_checkpoint_creates_file(tmp_path: Path) -> None:
    """save_checkpoint should create a JSON file in the checkpoints directory."""
    with patch("godrecon.core.checkpoint.Path.home", return_value=tmp_path):
        filepath = save_checkpoint(
            domain="example.com",
            completed_modules=["subdomains", "dns"],
            results={"subdomains": {"findings": []}, "dns": {"findings": []}},
        )

    assert os.path.exists(filepath)
    assert filepath.endswith(".json")


def test_save_checkpoint_filename_contains_domain(tmp_path: Path) -> None:
    """Checkpoint filename should contain the target domain."""
    with patch("godrecon.core.checkpoint.Path.home", return_value=tmp_path):
        filepath = save_checkpoint(
            domain="target.example.org",
            completed_modules=["subdomains"],
            results={},
        )

    assert "target.example.org" in os.path.basename(filepath)


def test_save_checkpoint_content(tmp_path: Path) -> None:
    """Checkpoint file should contain domain, timestamp, completed_modules, and results."""
    completed = ["subdomains", "ports"]
    results = {"subdomains": {"count": 5}, "ports": {"open": [80, 443]}}

    with patch("godrecon.core.checkpoint.Path.home", return_value=tmp_path):
        filepath = save_checkpoint(
            domain="example.com",
            completed_modules=completed,
            results=results,
        )

    with open(filepath) as f:
        data = json.load(f)

    assert data["domain"] == "example.com"
    assert isinstance(data["timestamp"], int)
    assert data["completed_modules"] == completed
    assert data["results"] == results


def test_save_checkpoint_creates_directory(tmp_path: Path) -> None:
    """save_checkpoint should create ~/.godrecon/checkpoints/ if it doesn't exist."""
    home = tmp_path / "new_home"
    home.mkdir()
    checkpoint_dir = home / ".godrecon" / "checkpoints"
    assert not checkpoint_dir.exists()

    with patch("godrecon.core.checkpoint.Path.home", return_value=home):
        save_checkpoint("example.com", [], {})

    assert checkpoint_dir.exists()


def test_save_checkpoint_returns_string_path(tmp_path: Path) -> None:
    """save_checkpoint should return a string path."""
    with patch("godrecon.core.checkpoint.Path.home", return_value=tmp_path):
        filepath = save_checkpoint("example.com", [], {})

    assert isinstance(filepath, str)


def test_save_checkpoint_non_serializable_values(tmp_path: Path) -> None:
    """save_checkpoint should not raise when results contain non-JSON-serializable objects."""

    class _Obj:
        def __str__(self) -> str:
            return "custom_object"

    with patch("godrecon.core.checkpoint.Path.home", return_value=tmp_path):
        filepath = save_checkpoint(
            domain="example.com",
            completed_modules=["mod"],
            results={"mod": _Obj()},
        )

    assert os.path.exists(filepath)


# ---------------------------------------------------------------------------
# load_checkpoint tests
# ---------------------------------------------------------------------------


def test_load_checkpoint_returns_dict(tmp_path: Path) -> None:
    """load_checkpoint should return a dict."""
    checkpoint_file = tmp_path / "example.com_1234567890.json"
    data = {
        "domain": "example.com",
        "timestamp": 1234567890,
        "completed_modules": ["subdomains"],
        "results": {},
    }
    checkpoint_file.write_text(json.dumps(data))

    result = load_checkpoint(str(checkpoint_file))

    assert isinstance(result, dict)
    assert result["domain"] == "example.com"
    assert result["completed_modules"] == ["subdomains"]
    assert result["timestamp"] == 1234567890


def test_load_checkpoint_roundtrip(tmp_path: Path) -> None:
    """Data saved by save_checkpoint should be loadable by load_checkpoint."""
    completed = ["subdomains", "dns", "ports"]
    results = {"subdomains": {"findings": ["sub.example.com"]}}

    with patch("godrecon.core.checkpoint.Path.home", return_value=tmp_path):
        filepath = save_checkpoint(
            domain="example.com",
            completed_modules=completed,
            results=results,
        )

    loaded = load_checkpoint(filepath)

    assert loaded["domain"] == "example.com"
    assert loaded["completed_modules"] == completed


def test_load_checkpoint_missing_file_raises() -> None:
    """load_checkpoint should raise an error when the file does not exist."""
    with pytest.raises((FileNotFoundError, OSError)):
        load_checkpoint("/tmp/nonexistent_checkpoint_file_xyz.json")


# ---------------------------------------------------------------------------
# Engine integration: skip_modules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_skip_modules_skips_completed() -> None:
    """Engine should skip modules listed in skip_modules."""
    from unittest.mock import patch

    from godrecon.core.config import Config
    from godrecon.core.engine import ScanEngine
    from godrecon.modules.base import BaseModule, ModuleResult

    class _TestModule(BaseModule):
        name = "test_skip_mod"
        description = "Test"
        category = "test"

        async def _execute(self, target: str, config: Config) -> ModuleResult:
            return ModuleResult(module_name=self.name, target=target)

    engine = ScanEngine(
        target="example.com",
        config=Config(),
        skip_modules={"test_skip_mod"},
    )

    from godrecon.core.engine import ScanResult

    result = ScanResult(target="example.com", started_at=0.0)
    await engine._run_module(_TestModule(), result)

    # Module should have been skipped
    assert "test_skip_mod" not in result.module_results


@pytest.mark.asyncio
async def test_engine_skip_modules_runs_non_skipped() -> None:
    """Engine should run modules NOT listed in skip_modules."""
    from unittest.mock import patch

    from godrecon.core.config import Config
    from godrecon.core.engine import ScanEngine, ScanResult
    from godrecon.modules.base import BaseModule, ModuleResult

    class _TestModule(BaseModule):
        name = "not_skipped_mod"
        description = "Test"
        category = "test"

        async def _execute(self, target: str, config: Config) -> ModuleResult:
            return ModuleResult(module_name=self.name, target=target)

    engine = ScanEngine(
        target="example.com",
        config=Config(),
        skip_modules={"some_other_module"},
    )

    result = ScanResult(target="example.com", started_at=0.0)

    with patch("godrecon.core.checkpoint.Path.home", return_value=Path("/tmp")):
        await engine._run_module(_TestModule(), result)

    assert "not_skipped_mod" in result.module_results
