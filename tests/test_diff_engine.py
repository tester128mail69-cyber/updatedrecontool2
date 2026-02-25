"""Tests for godrecon.core.diff_engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from godrecon.core.database import ScanDatabase
from godrecon.core.diff_engine import (
    DiffSection,
    ScanDiffEngine,
    ScanDiffReport,
    _extract_endpoints,
    _extract_headers,
    _extract_ports,
    _extract_subdomains,
    _extract_technologies,
    _extract_vulns,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> ScanDatabase:
    """Return a ScanDatabase backed by a temporary file."""
    return ScanDatabase(db_path=str(tmp_path / "test_scans.db"))


@pytest.fixture
def engine(db: ScanDatabase) -> ScanDiffEngine:
    """Return a ScanDiffEngine using the temporary database."""
    return ScanDiffEngine(db=db)


def _make_results(
    subdomains: list | None = None,
    ports: dict | None = None,
    findings: list | None = None,
    technologies: list | None = None,
    headers: dict | None = None,
    endpoints: list | None = None,
) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    if subdomains is not None:
        results["subdomains"] = {"data": {"subdomains": subdomains}}
    if ports is not None:
        results["ports"] = {"data": ports}
    if findings is not None:
        results["vulns"] = {"findings": findings}
    if technologies is not None:
        results["technologies"] = {"data": {"technologies": technologies}}
    if headers is not None:
        results["headers"] = {"data": {"headers": headers}}
    if endpoints is not None:
        results["crawl"] = {"data": {"endpoints": endpoints}}
    return results


# ---------------------------------------------------------------------------
# DiffSection
# ---------------------------------------------------------------------------


def test_diff_section_has_changes_when_added() -> None:
    s = DiffSection(added=["foo"])
    assert s.has_changes is True


def test_diff_section_has_changes_when_removed() -> None:
    s = DiffSection(removed=["bar"])
    assert s.has_changes is True


def test_diff_section_has_changes_when_changed() -> None:
    s = DiffSection(changed=[{"key": "k", "old": "a", "new": "b"}])
    assert s.has_changes is True


def test_diff_section_no_changes_when_empty() -> None:
    s = DiffSection()
    assert s.has_changes is False


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def test_extract_subdomains_returns_expected() -> None:
    r = _make_results(subdomains=["a.example.com", "b.example.com"])
    result = _extract_subdomains(r)
    assert result == {"a.example.com", "b.example.com"}


def test_extract_subdomains_empty() -> None:
    assert _extract_subdomains({}) == set()


def test_extract_ports_returns_expected() -> None:
    r = _make_results(ports={"10.0.0.1": {"open_ports": [80, 443]}})
    result = _extract_ports(r)
    assert "10.0.0.1:80" in result
    assert "10.0.0.1:443" in result


def test_extract_ports_empty() -> None:
    assert _extract_ports({}) == set()


def test_extract_vulns_returns_expected() -> None:
    r = _make_results(findings=[{"title": "SQLi", "severity": "critical"}])
    result = _extract_vulns(r)
    assert any("SQLi" in v for v in result)


def test_extract_vulns_empty() -> None:
    assert _extract_vulns({}) == set()


def test_extract_technologies_returns_expected() -> None:
    r = _make_results(technologies=["nginx", "react"])
    result = _extract_technologies(r)
    assert "nginx" in result
    assert "react" in result


def test_extract_technologies_empty() -> None:
    assert _extract_technologies({}) == set()


def test_extract_headers_returns_expected() -> None:
    r = _make_results(headers={"X-Frame-Options": "DENY", "Content-Type": "text/html"})
    result = _extract_headers(r)
    assert result.get("x-frame-options") == "DENY"


def test_extract_headers_empty() -> None:
    assert _extract_headers({}) == {}


def test_extract_endpoints_returns_expected() -> None:
    r = _make_results(endpoints=["https://example.com/api", "https://example.com/login"])
    result = _extract_endpoints(r)
    assert "https://example.com/api" in result


def test_extract_endpoints_empty() -> None:
    assert _extract_endpoints({}) == set()


# ---------------------------------------------------------------------------
# ScanDiffReport.to_dict / to_json / to_text
# ---------------------------------------------------------------------------


def test_report_to_dict_has_expected_keys() -> None:
    r = ScanDiffReport(scan1_id=1, scan2_id=2, scan1_domain="a.com", scan2_domain="a.com",
                       scan1_time=1000, scan2_time=2000)
    d = r.to_dict()
    for key in ("scan1_id", "scan2_id", "scan1_domain", "scan2_domain",
                "subdomains", "ports", "vulnerabilities", "technologies",
                "headers", "endpoints"):
        assert key in d


def test_report_to_json_is_valid_json() -> None:
    import json

    r = ScanDiffReport(scan1_id=1, scan2_id=2, scan1_domain="a.com", scan2_domain="a.com",
                       scan1_time=None, scan2_time=None)
    r.subdomains.added = ["new.a.com"]
    parsed = json.loads(r.to_json())
    assert parsed["subdomains"]["added"] == ["new.a.com"]


def test_report_to_text_no_changes() -> None:
    r = ScanDiffReport(scan1_id=1, scan2_id=2, scan1_domain="a.com", scan2_domain="a.com",
                       scan1_time=None, scan2_time=None)
    text = r.to_text()
    assert "No differences detected" in text


def test_report_to_text_with_changes() -> None:
    r = ScanDiffReport(scan1_id=1, scan2_id=2, scan1_domain="a.com", scan2_domain="a.com",
                       scan1_time=None, scan2_time=None)
    r.subdomains.added = ["new.a.com"]
    r.ports.removed = ["10.0.0.1:22"]
    text = r.to_text()
    assert "+ new.a.com" in text
    assert "- 10.0.0.1:22" in text


def test_report_has_changes_true() -> None:
    r = ScanDiffReport(scan1_id=1, scan2_id=2, scan1_domain="a.com", scan2_domain="a.com",
                       scan1_time=None, scan2_time=None)
    r.subdomains.added = ["x"]
    assert r.has_changes is True


def test_report_has_changes_false() -> None:
    r = ScanDiffReport(scan1_id=1, scan2_id=2, scan1_domain="a.com", scan2_domain="a.com",
                       scan1_time=None, scan2_time=None)
    assert r.has_changes is False


# ---------------------------------------------------------------------------
# ScanDiffEngine.diff (raw dict comparison)
# ---------------------------------------------------------------------------


def test_diff_detects_new_subdomain(engine: ScanDiffEngine) -> None:
    old = {"results": _make_results(subdomains=["a.example.com"])}
    new = {"results": _make_results(subdomains=["a.example.com", "b.example.com"])}
    report = engine.diff(old, new)
    assert "b.example.com" in report.subdomains.added
    assert report.subdomains.removed == []


def test_diff_detects_removed_subdomain(engine: ScanDiffEngine) -> None:
    old = {"results": _make_results(subdomains=["a.example.com", "b.example.com"])}
    new = {"results": _make_results(subdomains=["a.example.com"])}
    report = engine.diff(old, new)
    assert "b.example.com" in report.subdomains.removed
    assert report.subdomains.added == []


def test_diff_detects_new_port(engine: ScanDiffEngine) -> None:
    old = {"results": _make_results(ports={"10.0.0.1": {"open_ports": [80]}})}
    new = {"results": _make_results(ports={"10.0.0.1": {"open_ports": [80, 443]}})}
    report = engine.diff(old, new)
    assert "10.0.0.1:443" in report.ports.added


def test_diff_detects_closed_port(engine: ScanDiffEngine) -> None:
    old = {"results": _make_results(ports={"10.0.0.1": {"open_ports": [80, 22]}})}
    new = {"results": _make_results(ports={"10.0.0.1": {"open_ports": [80]}})}
    report = engine.diff(old, new)
    assert "10.0.0.1:22" in report.ports.removed


def test_diff_detects_new_vuln(engine: ScanDiffEngine) -> None:
    old = {"results": _make_results(findings=[])}
    new = {"results": _make_results(findings=[{"title": "XSS", "severity": "high"}])}
    report = engine.diff(old, new)
    assert any("XSS" in v for v in report.vulnerabilities.added)


def test_diff_detects_resolved_vuln(engine: ScanDiffEngine) -> None:
    old = {"results": _make_results(findings=[{"title": "XSS", "severity": "high"}])}
    new = {"results": _make_results(findings=[])}
    report = engine.diff(old, new)
    assert any("XSS" in v for v in report.vulnerabilities.removed)


def test_diff_detects_new_technology(engine: ScanDiffEngine) -> None:
    old = {"results": _make_results(technologies=["nginx"])}
    new = {"results": _make_results(technologies=["nginx", "react"])}
    report = engine.diff(old, new)
    assert "react" in report.technologies.added


def test_diff_detects_changed_header(engine: ScanDiffEngine) -> None:
    old = {"results": _make_results(headers={"X-Frame-Options": "SAMEORIGIN"})}
    new = {"results": _make_results(headers={"X-Frame-Options": "DENY"})}
    report = engine.diff(old, new)
    assert len(report.headers.changed) == 1
    assert report.headers.changed[0]["key"] == "x-frame-options"
    assert report.headers.changed[0]["old"] == "SAMEORIGIN"
    assert report.headers.changed[0]["new"] == "DENY"


def test_diff_detects_new_endpoint(engine: ScanDiffEngine) -> None:
    old = {"results": _make_results(endpoints=["https://example.com/"])}
    new = {"results": _make_results(endpoints=["https://example.com/", "https://example.com/api"])}
    report = engine.diff(old, new)
    assert "https://example.com/api" in report.endpoints.added


def test_diff_no_changes_identical_scans(engine: ScanDiffEngine) -> None:
    data = {"results": _make_results(subdomains=["a.example.com"], ports={"10.0.0.1": {"open_ports": [80]}})}
    report = engine.diff(data, data)
    assert report.has_changes is False


# ---------------------------------------------------------------------------
# ScanDiffEngine.diff_by_ids
# ---------------------------------------------------------------------------


def test_diff_by_ids_detects_new_subdomain(engine: ScanDiffEngine, db: ScanDatabase) -> None:
    id1 = db.save_scan("example.com", {}, _make_results(subdomains=["a.example.com"]))
    id2 = db.save_scan("example.com", {}, _make_results(subdomains=["a.example.com", "b.example.com"]))
    report = engine.diff_by_ids(id1, id2)
    assert "b.example.com" in report.subdomains.added


def test_diff_by_ids_raises_for_missing_scan1(engine: ScanDiffEngine, db: ScanDatabase) -> None:
    id2 = db.save_scan("example.com", {}, {})
    with pytest.raises(ValueError, match="99999"):
        engine.diff_by_ids(99999, id2)


def test_diff_by_ids_raises_for_missing_scan2(engine: ScanDiffEngine, db: ScanDatabase) -> None:
    id1 = db.save_scan("example.com", {}, {})
    with pytest.raises(ValueError, match="99999"):
        engine.diff_by_ids(id1, 99999)


def test_diff_by_ids_report_metadata(engine: ScanDiffEngine, db: ScanDatabase) -> None:
    id1 = db.save_scan("example.com", {}, {})
    id2 = db.save_scan("example.com", {}, {})
    report = engine.diff_by_ids(id1, id2)
    assert report.scan1_id == id1
    assert report.scan2_id == id2
    assert report.scan1_domain == "example.com"


# ---------------------------------------------------------------------------
# ScanDiffEngine.diff_latest
# ---------------------------------------------------------------------------


def test_diff_latest_compares_two_most_recent(engine: ScanDiffEngine, db: ScanDatabase) -> None:
    db.save_scan("example.com", {}, _make_results(subdomains=["a.example.com"]))
    db.save_scan("example.com", {}, _make_results(subdomains=["a.example.com", "b.example.com"]))
    report = engine.diff_latest("example.com")
    assert "b.example.com" in report.subdomains.added


def test_diff_latest_raises_with_only_one_scan(engine: ScanDiffEngine, db: ScanDatabase) -> None:
    db.save_scan("example.com", {}, {})
    with pytest.raises(ValueError, match="at least 2"):
        engine.diff_latest("example.com")


def test_diff_latest_raises_with_no_scans(engine: ScanDiffEngine) -> None:
    with pytest.raises(ValueError, match="at least 2"):
        engine.diff_latest("missing.example.com")


def test_diff_latest_ignores_other_domains(engine: ScanDiffEngine, db: ScanDatabase) -> None:
    db.save_scan("other.com", {}, _make_results(subdomains=["x.other.com"]))
    db.save_scan("example.com", {}, _make_results(subdomains=["a.example.com"]))
    db.save_scan("example.com", {}, _make_results(subdomains=["a.example.com", "b.example.com"]))
    report = engine.diff_latest("example.com")
    assert "b.example.com" in report.subdomains.added
    assert not any("other.com" in s for s in report.subdomains.added)
