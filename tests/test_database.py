"""Tests for godrecon.core.database."""

from __future__ import annotations

from pathlib import Path

import pytest

from godrecon.core.database import ScanDatabase


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> ScanDatabase:
    """Return a ScanDatabase backed by a temporary file."""
    return ScanDatabase(db_path=str(tmp_path / "test_scans.db"))


# ---------------------------------------------------------------------------
# __init__ / table creation
# ---------------------------------------------------------------------------


def test_init_creates_db_file(tmp_path: Path) -> None:
    """ScanDatabase.__init__ should create the database file."""
    db_file = tmp_path / "scans.db"
    assert not db_file.exists()
    ScanDatabase(db_path=str(db_file))
    assert db_file.exists()


def test_init_creates_parent_directory(tmp_path: Path) -> None:
    """ScanDatabase.__init__ should create missing parent directories."""
    db_file = tmp_path / "nested" / "dir" / "scans.db"
    ScanDatabase(db_path=str(db_file))
    assert db_file.exists()


def test_init_idempotent(tmp_path: Path) -> None:
    """Creating a ScanDatabase twice on the same file should not raise."""
    db_file = tmp_path / "scans.db"
    ScanDatabase(db_path=str(db_file))
    ScanDatabase(db_path=str(db_file))  # should not raise


# ---------------------------------------------------------------------------
# save_scan
# ---------------------------------------------------------------------------


def test_save_scan_returns_int(db: ScanDatabase) -> None:
    """save_scan should return an integer scan ID."""
    scan_id = db.save_scan("example.com", {}, {})
    assert isinstance(scan_id, int)
    assert scan_id > 0


def test_save_scan_increments_id(db: ScanDatabase) -> None:
    """Consecutive saves should return incrementing IDs."""
    id1 = db.save_scan("example.com", {}, {})
    id2 = db.save_scan("example.com", {}, {})
    assert id2 > id1


def test_save_scan_stores_domain(db: ScanDatabase) -> None:
    """save_scan should store the domain correctly."""
    scan_id = db.save_scan("target.example.org", {}, {})
    scan = db.get_scan(scan_id)
    assert scan is not None
    assert scan["domain"] == "target.example.org"


def test_save_scan_stores_config(db: ScanDatabase) -> None:
    """save_scan should persist the config dict."""
    cfg = {"timeout": 30, "threads": 5}
    scan_id = db.save_scan("example.com", cfg, {})
    scan = db.get_scan(scan_id)
    assert scan is not None
    assert scan["config"] == cfg


def test_save_scan_stores_results(db: ScanDatabase) -> None:
    """save_scan should persist the results dict."""
    results = {"subdomains": ["a.example.com", "b.example.com"], "ports": [80, 443]}
    scan_id = db.save_scan("example.com", {}, results)
    scan = db.get_scan(scan_id)
    assert scan is not None
    assert scan["results"] == results


def test_save_scan_records_modules(db: ScanDatabase) -> None:
    """save_scan should create a modules row for each result key."""
    results = {"subdomains": [], "dns": [], "ports": []}
    scan_id = db.save_scan("example.com", {}, results)
    scan = db.get_scan(scan_id)
    assert scan is not None
    module_names = {m["name"] for m in scan["modules"]}
    assert module_names == {"subdomains", "dns", "ports"}


# ---------------------------------------------------------------------------
# get_scan
# ---------------------------------------------------------------------------


def test_get_scan_returns_none_for_missing(db: ScanDatabase) -> None:
    """get_scan should return None when the scan ID does not exist."""
    assert db.get_scan(99999) is None


def test_get_scan_has_expected_keys(db: ScanDatabase) -> None:
    """get_scan result should contain all expected top-level keys."""
    scan_id = db.save_scan("example.com", {}, {})
    scan = db.get_scan(scan_id)
    assert scan is not None
    for key in ("id", "domain", "config", "started_at", "finished_at", "results", "modules"):
        assert key in scan


def test_get_scan_id_matches(db: ScanDatabase) -> None:
    """get_scan should return the correct scan ID."""
    scan_id = db.save_scan("example.com", {}, {})
    scan = db.get_scan(scan_id)
    assert scan is not None
    assert scan["id"] == scan_id


# ---------------------------------------------------------------------------
# list_scans
# ---------------------------------------------------------------------------


def test_list_scans_empty(db: ScanDatabase) -> None:
    """list_scans should return an empty list when there are no scans."""
    assert db.list_scans() == []


def test_list_scans_returns_all(db: ScanDatabase) -> None:
    """list_scans should return one entry per saved scan."""
    db.save_scan("a.example.com", {}, {})
    db.save_scan("b.example.com", {}, {})
    scans = db.list_scans()
    assert len(scans) == 2


def test_list_scans_summary_keys(db: ScanDatabase) -> None:
    """Each list_scans entry should have id, domain, started_at, finished_at."""
    db.save_scan("example.com", {}, {})
    scans = db.list_scans()
    assert len(scans) == 1
    for key in ("id", "domain", "started_at", "finished_at"):
        assert key in scans[0]


def test_list_scans_ordered_by_started_at_desc(db: ScanDatabase) -> None:
    """list_scans should return newest scans first."""
    id1 = db.save_scan("first.example.com", {}, {})
    id2 = db.save_scan("second.example.com", {}, {})
    scans = db.list_scans()
    ids = [s["id"] for s in scans]
    assert ids.index(id2) < ids.index(id1)


# ---------------------------------------------------------------------------
# delete_scan
# ---------------------------------------------------------------------------


def test_delete_scan_returns_true_on_success(db: ScanDatabase) -> None:
    """delete_scan should return True when a scan is deleted."""
    scan_id = db.save_scan("example.com", {}, {})
    assert db.delete_scan(scan_id) is True


def test_delete_scan_returns_false_when_missing(db: ScanDatabase) -> None:
    """delete_scan should return False when the scan ID does not exist."""
    assert db.delete_scan(99999) is False


def test_delete_scan_removes_scan(db: ScanDatabase) -> None:
    """delete_scan should remove the scan so get_scan returns None."""
    scan_id = db.save_scan("example.com", {}, {})
    db.delete_scan(scan_id)
    assert db.get_scan(scan_id) is None


def test_delete_scan_not_in_list_scans(db: ScanDatabase) -> None:
    """Deleted scans should not appear in list_scans."""
    scan_id = db.save_scan("example.com", {}, {})
    db.delete_scan(scan_id)
    ids = [s["id"] for s in db.list_scans()]
    assert scan_id not in ids
