"""Async task scheduler with concurrency control, rate limiting, and retries.

Provides a priority queue–based scheduler that limits concurrency per target,
applies exponential backoff on failures, and reports progress in real time.

Also provides :class:`ScanScheduler` for cron-based recurring scans backed by
a local SQLite database.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional


class Priority(IntEnum):
    """Task priority levels (lower value = higher priority)."""

    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass(order=True)
class Task:
    """A unit of work managed by the scheduler.

    Attributes:
        priority: Execution priority (lower = runs first).
        name: Human-readable task identifier.
        coro_factory: Callable that returns the coroutine to execute.
        max_retries: How many times to retry on failure.
        retry_delay: Base delay in seconds for exponential backoff.
    """

    priority: int
    name: str = field(compare=False)
    coro_factory: Callable[[], Awaitable[Any]] = field(compare=False)
    max_retries: int = field(default=3, compare=False)
    retry_delay: float = field(default=1.0, compare=False)


class Scheduler:
    """Async task queue with configurable concurrency and rate limiting.

    Example::

        scheduler = Scheduler(concurrency=20, rate_limit=10)
        await scheduler.start()
        await scheduler.submit(Task(Priority.NORMAL, "dns", dns_coro_factory))
        results = await scheduler.join()
        await scheduler.stop()
    """

    def __init__(
        self,
        concurrency: int = 50,
        rate_limit: float = 0.0,
    ) -> None:
        """Initialise the scheduler.

        Args:
            concurrency: Maximum number of concurrent tasks.
            rate_limit: Minimum seconds between task starts (0 = unlimited).
        """
        self._concurrency = concurrency
        self._rate_limit = rate_limit
        self._queue: asyncio.PriorityQueue[Task] = asyncio.PriorityQueue()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._results: List[Any] = []
        self._errors: List[Dict[str, Any]] = []
        self._workers: List[asyncio.Task[None]] = []
        self._running = False
        self._last_start: float = 0.0
        self._completed = 0
        self._total = 0

    async def start(self) -> None:
        """Initialise internal semaphore and mark the scheduler as running."""
        self._semaphore = asyncio.Semaphore(self._concurrency)
        self._running = True

    async def stop(self) -> None:
        """Signal all workers to stop and wait for them to finish."""
        self._running = False
        for worker in self._workers:
            worker.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def submit(self, task: Task) -> None:
        """Enqueue *task* for execution.

        Args:
            task: The :class:`Task` to schedule.
        """
        self._total += 1
        await self._queue.put(task)

    async def run_all(self) -> List[Any]:
        """Process all enqueued tasks and return aggregated results.

        Returns:
            List of successful task return values.
        """
        workers = [
            asyncio.create_task(self._worker())
            for _ in range(min(self._concurrency, max(1, self._total)))
        ]
        await self._queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        return list(self._results)

    async def _worker(self) -> None:
        """Internal worker coroutine: pull tasks and execute them."""
        while True:
            task = await self._queue.get()
            try:
                await self._execute(task)
            finally:
                self._queue.task_done()

    async def _execute(self, task: Task) -> None:
        """Execute a single *task* with retry/backoff logic.

        Args:
            task: The task to execute.
        """
        assert self._semaphore is not None

        for attempt in range(task.max_retries + 1):
            async with self._semaphore:
                # Rate limiting
                if self._rate_limit > 0:
                    now = time.monotonic()
                    wait = self._rate_limit - (now - self._last_start)
                    if wait > 0:
                        await asyncio.sleep(wait)
                    self._last_start = time.monotonic()

                try:
                    result = await task.coro_factory()
                    self._results.append(result)
                    self._completed += 1
                    return
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    if attempt < task.max_retries:
                        backoff = task.retry_delay * (2 ** attempt)
                        await asyncio.sleep(backoff)
                    else:
                        self._errors.append({"task": task.name, "error": str(exc)})
                        self._completed += 1

    @property
    def completed(self) -> int:
        """Number of tasks completed (success + failure)."""
        return self._completed

    @property
    def total(self) -> int:
        """Total number of tasks submitted."""
        return self._total

    @property
    def errors(self) -> List[Dict[str, Any]]:
        """List of task error records."""
        return list(self._errors)

    @property
    def progress(self) -> float:
        """Completion percentage (0.0–100.0)."""
        if self._total == 0:
            return 0.0
        return (self._completed / self._total) * 100.0


# ---------------------------------------------------------------------------
# Cron-based ScanScheduler backed by SQLite
# ---------------------------------------------------------------------------


def _cron_field_matches(field_str: str, value: int, min_val: int, max_val: int) -> bool:
    """Return True if *value* satisfies the cron *field_str*.

    Supports ``*``, ``*/step``, ``a-b``, and comma-separated lists.
    """
    for part in field_str.split(","):
        part = part.strip()
        if part == "*":
            return True
        if part.startswith("*/"):
            try:
                step = int(part[2:])
                if step > 0 and (value - min_val) % step == 0:
                    return True
            except ValueError:
                pass
        elif "-" in part:
            bounds = part.split("-", 1)
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
                if lo <= value <= hi:
                    return True
            except ValueError:
                pass
        else:
            try:
                if int(part) == value:
                    return True
            except ValueError:
                pass
    return False


def _next_cron_ts(cron_expr: str, after: Optional[float] = None) -> float:
    """Compute the next Unix timestamp for *cron_expr* after *after*.

    Args:
        cron_expr: Five-field cron expression (``minute hour dom month dow``).
        after: Reference Unix timestamp.  Defaults to ``time.time()``.

    Returns:
        Unix timestamp of the next matching minute.

    Raises:
        ValueError: If *cron_expr* does not have exactly five fields.
    """
    fields = cron_expr.strip().split()
    if len(fields) != 5:
        raise ValueError(
            f"Invalid cron expression {cron_expr!r}: expected 5 fields, got {len(fields)}"
        )
    minute_f, hour_f, dom_f, month_f, dow_f = fields

    base_ts = (after or time.time()) + 60  # start from next minute
    # Truncate to minute boundary
    dt = datetime.fromtimestamp(base_ts, tz=timezone.utc).replace(second=0, microsecond=0)

    for _ in range(366 * 24 * 60):  # at most ~1 year of minutes
        # Standard cron dow: Sunday=0, Monday=1, ..., Saturday=6
        cron_dow = (dt.weekday() + 1) % 7
        if (
            _cron_field_matches(month_f, dt.month, 1, 12)
            and _cron_field_matches(dom_f, dt.day, 1, 31)
            and _cron_field_matches(dow_f, cron_dow, 0, 6)
            and _cron_field_matches(hour_f, dt.hour, 0, 23)
            and _cron_field_matches(minute_f, dt.minute, 0, 59)
        ):
            return dt.timestamp()
        dt += timedelta(minutes=1)

    raise ValueError(f"Could not compute next run for cron expression {cron_expr!r}")


@dataclass
class ScheduledJob:
    """A persisted cron-scheduled scan job.

    Attributes:
        job_id: Unique UUID string.
        target: Scan target (domain, IP, CIDR).
        cron_expr: Five-field cron expression.
        enabled: Whether this job is active.
        created_at: Unix timestamp of creation.
        last_run: Unix timestamp of last execution or ``None``.
        next_run: Unix timestamp of next scheduled run.
    """

    job_id: str
    target: str
    cron_expr: str
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    last_run: Optional[float] = None
    next_run: float = field(default_factory=time.time)


_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    job_id      TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    cron_expr   TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  REAL NOT NULL,
    last_run    REAL,
    next_run    REAL NOT NULL
)
"""


class ScanScheduler:
    """Cron-based recurring scan scheduler backed by a local SQLite database.

    Supports cron expressions (``minute hour dom month dow``), persists all
    jobs in SQLite, and runs a background daemon thread that fires the
    provided callback whenever a job is due.

    Example::

        def on_scan(job: ScheduledJob) -> None:
            print(f"Running scan for {job.target}")

        scheduler = ScanScheduler()
        scheduler.add("example.com", "0 2 * * *")
        scheduler.start(on_scan)
        # ...
        scheduler.stop()
    """

    #: Interval in seconds between checks in the background thread.
    POLL_INTERVAL: int = 30

    def __init__(self, db_path: Optional[str] = None, poll_interval: int = 30) -> None:
        """Initialise the scheduler.

        Args:
            db_path: Path to the SQLite database file.  Defaults to
                     ``~/.godrecon/scheduler.db``.
            poll_interval: Seconds between background-thread polling ticks.
                           Defaults to 30.  Lower values are useful for tests.
        """
        if db_path is None:
            db_path = str(Path.home() / ".godrecon" / "scheduler.db")
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.POLL_INTERVAL = poll_interval
        self._init_db()

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE)

    def _row_to_job(self, row: sqlite3.Row) -> ScheduledJob:
        return ScheduledJob(
            job_id=row["job_id"],
            target=row["target"],
            cron_expr=row["cron_expr"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
            last_run=row["last_run"],
            next_run=row["next_run"],
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, target: str, cron_expr: str) -> ScheduledJob:
        """Add a new cron-scheduled scan job.

        Args:
            target: Domain/IP/CIDR to scan.
            cron_expr: Five-field cron expression (e.g. ``"0 2 * * *"``).

        Returns:
            The created :class:`ScheduledJob`.

        Raises:
            ValueError: If *cron_expr* is invalid.
        """
        now = time.time()
        next_run = _next_cron_ts(cron_expr, after=now)
        job = ScheduledJob(
            job_id=str(uuid.uuid4()),
            target=target,
            cron_expr=cron_expr,
            created_at=now,
            next_run=next_run,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO scheduled_jobs "
                "(job_id, target, cron_expr, enabled, created_at, last_run, next_run) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (job.job_id, job.target, job.cron_expr, int(job.enabled),
                 job.created_at, job.last_run, job.next_run,),
            )
        return job

    def remove(self, job_id: str) -> bool:
        """Remove a scheduled job by ID.

        Args:
            job_id: UUID of the job to remove.

        Returns:
            ``True`` if the job was found and deleted, ``False`` otherwise.
        """
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM scheduled_jobs WHERE job_id = ?", (job_id,)
            )
            return cur.rowcount > 0

    def list_jobs(self) -> List[ScheduledJob]:
        """Return all scheduled jobs.

        Returns:
            List of :class:`ScheduledJob` objects ordered by ``next_run``.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scheduled_jobs ORDER BY next_run ASC"
            ).fetchall()
        return [self._row_to_job(r) for r in rows]

    def get(self, job_id: str) -> Optional[ScheduledJob]:
        """Retrieve a single job by ID.

        Args:
            job_id: UUID string.

        Returns:
            :class:`ScheduledJob` or ``None`` if not found.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scheduled_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return self._row_to_job(row) if row else None

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------

    def start(self, callback: Callable[["ScheduledJob"], Any]) -> None:
        """Start the background daemon thread that fires *callback* for due jobs.

        Args:
            callback: Callable invoked with a :class:`ScheduledJob` when it
                      is due.  Exceptions are caught and logged; they will not
                      stop the background thread.
        """
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop,
            args=(callback,),
            daemon=True,
            name="ScanScheduler",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the background daemon thread."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=self.POLL_INTERVAL + 5)
            self._thread = None

    def _loop(self, callback: Callable[["ScheduledJob"], Any]) -> None:
        """Internal polling loop executed in the background thread."""
        import logging
        _log = logging.getLogger(__name__)

        while self._running:
            now = time.time()
            with self._connect() as conn:
                due_rows = conn.execute(
                    "SELECT * FROM scheduled_jobs WHERE enabled = 1 AND next_run <= ?",
                    (now,),
                ).fetchall()

            for row in due_rows:
                job = self._row_to_job(row)
                try:
                    callback(job)
                except Exception:  # noqa: BLE001
                    _log.exception("Error running scheduled scan for %s", job.target)
                finally:
                    last_run = time.time()
                    try:
                        next_run = _next_cron_ts(job.cron_expr, after=last_run)
                    except ValueError:
                        next_run = last_run + 86400
                    with self._lock, self._connect() as conn:
                        conn.execute(
                            "UPDATE scheduled_jobs SET last_run = ?, next_run = ? "
                            "WHERE job_id = ?",
                            (last_run, next_run, job.job_id),
                        )

            time.sleep(self.POLL_INTERVAL)

