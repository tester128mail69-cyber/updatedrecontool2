"""Tests for godrecon.core.reporter.ReportGenerator."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict

import pytest

from godrecon.core.reporter import ReportGenerator
from godrecon.modules.base import Finding, ModuleResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    title: str = "Test Finding",
    severity: str = "high",
    description: str = "A test finding.",
    tags: list | None = None,
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=severity,
        confidence=0.9,
        source_module="test_module",
        evidence="some evidence",
        data={"key": "value"},
        tags=tags or ["test", "demo"],
    )


def _make_scan_results(num_findings: int = 2) -> Dict[str, Any]:
    findings = [_make_finding(f"Finding {i}", "high" if i % 2 == 0 else "medium")
                for i in range(num_findings)]
    mr = ModuleResult(
        module_name="test_module",
        target="example.com",
        findings=findings,
    )
    return {
        "target": "example.com",
        "started_at": 1700000000.0,
        "finished_at": 1700000060.0,
        "module_results": {"test_module": mr},
        "errors": [],
        "stats": {},
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def test_generate_json(tmp_path):
    gen = ReportGenerator()
    output = tmp_path / "report.json"
    result = gen.generate_json(_make_scan_results(), str(output))
    assert result == output
    assert output.exists()
    data = json.loads(output.read_text())
    assert data["scan"]["target"] == "example.com"
    assert "findings" in data


def test_generate_json_via_generate(tmp_path):
    gen = ReportGenerator()
    output = str(tmp_path / "report.json")
    gen.generate(_make_scan_results(), output, fmt="json")
    assert Path(output).exists()


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def test_generate_csv(tmp_path):
    gen = ReportGenerator()
    output = tmp_path / "findings.csv"
    result = gen.generate_csv(_make_scan_results(3), str(output))
    assert result == output
    assert output.exists()
    rows = list(csv.DictReader(output.read_text().splitlines()))
    assert len(rows) == 3
    for row in rows:
        assert "severity" in row
        assert "title" in row


def test_generate_csv_via_generate(tmp_path):
    gen = ReportGenerator()
    output = str(tmp_path / "findings.csv")
    gen.generate(_make_scan_results(), output, fmt="csv")
    assert Path(output).exists()


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def test_generate_markdown(tmp_path):
    gen = ReportGenerator()
    output = tmp_path / "report.md"
    result = gen.generate_markdown(_make_scan_results(), str(output))
    assert result == output
    assert output.exists()
    content = output.read_text()
    assert "GODRECON" in content
    assert "example.com" in content


def test_generate_markdown_via_generate(tmp_path):
    gen = ReportGenerator()
    output = str(tmp_path / "report.md")
    gen.generate(_make_scan_results(), output, fmt="md")
    assert Path(output).exists()


def test_generate_markdown_via_generate_full_name(tmp_path):
    gen = ReportGenerator()
    output = str(tmp_path / "report.md")
    gen.generate(_make_scan_results(), output, fmt="markdown")
    assert Path(output).exists()


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def test_generate_html(tmp_path):
    gen = ReportGenerator()
    output = tmp_path / "report.html"
    result = gen.generate_html(_make_scan_results(), str(output))
    assert result == output
    assert output.exists()
    content = output.read_text()
    assert "GODRECON" in content
    assert "example.com" in content
    assert "<html" in content.lower()


def test_generate_html_via_generate(tmp_path):
    gen = ReportGenerator()
    output = str(tmp_path / "report.html")
    gen.generate(_make_scan_results(), output, fmt="html")
    assert Path(output).exists()


# ---------------------------------------------------------------------------
# Empty findings
# ---------------------------------------------------------------------------

def test_generate_json_no_findings(tmp_path):
    gen = ReportGenerator()
    output = str(tmp_path / "empty.json")
    gen.generate(_make_scan_results(0), output, fmt="json")
    data = json.loads(Path(output).read_text())
    assert data["summary"]["total_findings"] == 0


def test_generate_csv_no_findings(tmp_path):
    gen = ReportGenerator()
    output = str(tmp_path / "empty.csv")
    gen.generate(_make_scan_results(0), output, fmt="csv")
    rows = list(csv.DictReader(Path(output).read_text().splitlines()))
    assert rows == []


# ---------------------------------------------------------------------------
# Invalid format
# ---------------------------------------------------------------------------

def test_generate_invalid_format(tmp_path):
    gen = ReportGenerator()
    with pytest.raises(ValueError, match="Unsupported report format"):
        gen.generate({}, str(tmp_path / "report.xyz"), fmt="xyz")


# ---------------------------------------------------------------------------
# Parent directory creation
# ---------------------------------------------------------------------------

def test_generate_creates_parent_dirs(tmp_path):
    gen = ReportGenerator()
    nested = str(tmp_path / "a" / "b" / "report.json")
    gen.generate(_make_scan_results(), nested, fmt="json")
    assert Path(nested).exists()
