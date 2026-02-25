"""Tests for --quiet/-q and --verbose/-v CLI logging flags."""

from __future__ import annotations

import logging

import pytest

from godrecon.utils.logger import configure_logging


def test_default_log_level_is_info():
    configure_logging()
    root = logging.getLogger("godrecon")
    assert root.level == logging.INFO


def test_verbose_sets_debug_level():
    configure_logging(verbose=True)
    root = logging.getLogger("godrecon")
    assert root.level == logging.DEBUG


def test_quiet_sets_error_level():
    configure_logging(quiet=True)
    root = logging.getLogger("godrecon")
    assert root.level == logging.ERROR


def test_verbose_takes_precedence_over_base_level():
    configure_logging(level=logging.WARNING, verbose=True)
    root = logging.getLogger("godrecon")
    assert root.level == logging.DEBUG


def test_quiet_takes_precedence_over_base_level():
    configure_logging(level=logging.WARNING, quiet=True)
    root = logging.getLogger("godrecon")
    assert root.level == logging.ERROR


def test_scan_command_rejects_verbose_and_quiet_together():
    from typer.testing import CliRunner
    from godrecon.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--target", "example.com", "--verbose", "--quiet"])
    assert result.exit_code != 0


def test_scan_command_accepts_verbose_flag():
    from unittest.mock import patch, AsyncMock
    from typer.testing import CliRunner
    from godrecon.cli import app

    runner = CliRunner()
    with patch("godrecon.cli.configure_logging") as mock_log, \
         patch("godrecon.cli._run_scan", new=AsyncMock()):
        result = runner.invoke(app, ["scan", "--target", "example.com", "--verbose"])
    mock_log.assert_called_once_with(verbose=True, quiet=False)


def test_scan_command_accepts_quiet_flag():
    from unittest.mock import patch, AsyncMock
    from typer.testing import CliRunner
    from godrecon.cli import app

    runner = CliRunner()
    with patch("godrecon.cli.configure_logging") as mock_log, \
         patch("godrecon.cli._run_scan", new=AsyncMock()):
        result = runner.invoke(app, ["scan", "--target", "example.com", "--quiet"])
    mock_log.assert_called_once_with(verbose=False, quiet=True)


def test_scan_command_default_no_verbose_no_quiet():
    from unittest.mock import patch, AsyncMock
    from typer.testing import CliRunner
    from godrecon.cli import app

    runner = CliRunner()
    with patch("godrecon.cli.configure_logging") as mock_log, \
         patch("godrecon.cli._run_scan", new=AsyncMock()):
        result = runner.invoke(app, ["scan", "--target", "example.com"])
    mock_log.assert_called_once_with(verbose=False, quiet=False)
