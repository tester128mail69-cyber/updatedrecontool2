"""Tests for godrecon.core.scheduler.ScanScheduler and cron helpers."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from godrecon.core.scheduler import (
    ScanScheduler,
    ScheduledJob,
    _cron_field_matches,
    _next_cron_ts,
)


# ---------------------------------------------------------------------------
# Cron field matcher tests
# ---------------------------------------------------------------------------


def test_cron_field_star():
    assert _cron_field_matches("*", 0, 0, 59) is True
    assert _cron_field_matches("*", 59, 0, 59) is True


def test_cron_field_exact():
    assert _cron_field_matches("5", 5, 0, 59) is True
    assert _cron_field_matches("5", 6, 0, 59) is False


def test_cron_field_range():
    assert _cron_field_matches("0-5", 3, 0, 59) is True
    assert _cron_field_matches("0-5", 6, 0, 59) is False


def test_cron_field_step():
    assert _cron_field_matches("*/15", 0, 0, 59) is True
    assert _cron_field_matches("*/15", 15, 0, 59) is True
    assert _cron_field_matches("*/15", 30, 0, 59) is True
    assert _cron_field_matches("*/15", 7, 0, 59) is False


def test_cron_field_list():
    assert _cron_field_matches("1,3,5", 3, 0, 59) is True
    assert _cron_field_matches("1,3,5", 4, 0, 59) is False


# ---------------------------------------------------------------------------
# Next-cron-ts tests
# ---------------------------------------------------------------------------


def test_next_cron_ts_returns_future():
    now = time.time()
    ts = _next_cron_ts("* * * * *", after=now)
    assert ts > now


def test_next_cron_ts_at_midnight():
    # "0 0 * * *" should always be in the future
    now = time.time()
    ts = _next_cron_ts("0 0 * * *", after=now)
    assert ts > now


def test_next_cron_ts_invalid():
    with pytest.raises(ValueError, match="5 fields"):
        _next_cron_ts("* * * *")  # only 4 fields


def test_next_cron_ts_every_minute_advances():
    now = time.time()
    ts1 = _next_cron_ts("* * * * *", after=now)
    ts2 = _next_cron_ts("* * * * *", after=ts1)
    assert ts2 > ts1


# ---------------------------------------------------------------------------
# ScanScheduler persistence tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def scheduler(tmp_path: Path) -> ScanScheduler:
    db = tmp_path / "test_scheduler.db"
    return ScanScheduler(db_path=str(db))


def test_add_and_list(scheduler: ScanScheduler) -> None:
    job = scheduler.add("example.com", "0 2 * * *")
    assert isinstance(job, ScheduledJob)
    assert job.target == "example.com"
    assert job.cron_expr == "0 2 * * *"
    assert job.enabled is True
    assert job.job_id

    jobs = scheduler.list_jobs()
    assert len(jobs) == 1
    assert jobs[0].job_id == job.job_id


def test_add_sets_next_run_in_future(scheduler: ScanScheduler) -> None:
    now = time.time()
    job = scheduler.add("example.com", "* * * * *")
    assert job.next_run > now


def test_add_invalid_cron_raises(scheduler: ScanScheduler) -> None:
    with pytest.raises(ValueError):
        scheduler.add("example.com", "bad cron")


def test_remove_existing(scheduler: ScanScheduler) -> None:
    job = scheduler.add("example.com", "0 6 * * *")
    result = scheduler.remove(job.job_id)
    assert result is True
    assert scheduler.list_jobs() == []


def test_remove_missing(scheduler: ScanScheduler) -> None:
    result = scheduler.remove("nonexistent-id")
    assert result is False


def test_get_existing(scheduler: ScanScheduler) -> None:
    job = scheduler.add("example.com", "0 6 * * *")
    found = scheduler.get(job.job_id)
    assert found is not None
    assert found.job_id == job.job_id
    assert found.target == "example.com"


def test_get_missing(scheduler: ScanScheduler) -> None:
    assert scheduler.get("nope") is None


def test_multiple_jobs_list_ordered(scheduler: ScanScheduler) -> None:
    j1 = scheduler.add("a.com", "0 1 * * *")
    j2 = scheduler.add("b.com", "0 2 * * *")
    jobs = scheduler.list_jobs()
    assert len(jobs) == 2
    # All are ordered by next_run asc
    assert jobs[0].next_run <= jobs[1].next_run


def test_persistence_across_instances(tmp_path: Path) -> None:
    db = tmp_path / "persist.db"
    s1 = ScanScheduler(db_path=str(db))
    job = s1.add("persist.com", "0 12 * * *")

    s2 = ScanScheduler(db_path=str(db))
    jobs = s2.list_jobs()
    assert len(jobs) == 1
    assert jobs[0].job_id == job.job_id


# ---------------------------------------------------------------------------
# Background thread test
# ---------------------------------------------------------------------------


def test_background_thread_triggers_callback(tmp_path: Path) -> None:
    """Verify the background thread fires the callback for overdue jobs."""
    import sqlite3

    db = tmp_path / "bg.db"
    scheduler = ScanScheduler(db_path=str(db))

    # Insert a job whose next_run is in the past so it fires immediately
    past_ts = time.time() - 60
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "INSERT INTO scheduled_jobs "
            "(job_id, target, cron_expr, enabled, created_at, last_run, next_run) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("test-id", "trigger.com", "* * * * *", 1, past_ts, None, past_ts),
        )

    triggered = []

    def callback(job: ScheduledJob) -> None:
        triggered.append(job.job_id)

    scheduler = ScanScheduler(db_path=str(db), poll_interval=1)
    scheduler.start(callback)
    time.sleep(2)
    scheduler.stop()

    assert "test-id" in triggered


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


def test_config_has_scheduler_section() -> None:
    from godrecon.core.config import Config, SchedulerConfig

    cfg = Config()
    assert hasattr(cfg, "scheduler")
    assert isinstance(cfg.scheduler, SchedulerConfig)
    assert cfg.scheduler.enabled is True
    assert "scheduler" in cfg.scheduler.db_path


def test_scheduler_config_defaults() -> None:
    from godrecon.core.config import SchedulerConfig

    sc = SchedulerConfig()
    assert sc.enabled is True
    assert sc.db_path == "~/.godrecon/scheduler.db"
