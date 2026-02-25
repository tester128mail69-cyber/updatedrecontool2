"""SQLite-backed scan storage for GODRECON.

Provides a simple interface for persisting scan results without an ORM.
The default database lives at ``~/.godrecon/scans.db``.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


_DEFAULT_DB_PATH = Path.home() / ".godrecon" / "scans.db"


class ScanDatabase:
    """Lightweight SQLite database for storing GODRECON scan data.

    Args:
        db_path: Path to the SQLite database file.  Defaults to
            ``~/.godrecon/scans.db``.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            path = _DEFAULT_DB_PATH
        else:
            path = Path(db_path)

        path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = str(path)
        self._create_tables()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _create_tables(self) -> None:
        """Create the database schema if it does not already exist."""
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain    TEXT    NOT NULL,
                    config    TEXT    NOT NULL DEFAULT '{}',
                    started_at INTEGER NOT NULL,
                    finished_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS results (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    data    TEXT    NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS modules (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    name    TEXT    NOT NULL,
                    status  TEXT    NOT NULL DEFAULT 'completed'
                );
                """
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_scan(
        self,
        domain: str,
        config: Dict[str, Any],
        results: Dict[str, Any],
    ) -> int:
        """Persist a completed scan and return the new scan ID.

        Args:
            domain: The scan target domain.
            config: Serialisable configuration mapping used for the scan.
            results: Mapping of module name to its result data.

        Returns:
            The auto-assigned integer scan ID.
        """
        now = int(time.time())
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans (domain, config, started_at, finished_at) VALUES (?, ?, ?, ?)",
                (domain, json.dumps(config, default=str), now, now),
            )
            scan_id: int = cursor.lastrowid  # type: ignore[assignment]

            conn.execute(
                "INSERT INTO results (scan_id, data) VALUES (?, ?)",
                (scan_id, json.dumps(results, default=str)),
            )

            for module_name in results:
                conn.execute(
                    "INSERT INTO modules (scan_id, name, status) VALUES (?, ?, ?)",
                    (scan_id, module_name, "completed"),
                )

        return scan_id

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single scan by its ID.

        Args:
            scan_id: The numeric scan identifier.

        Returns:
            A dictionary with ``id``, ``domain``, ``config``, ``started_at``,
            ``finished_at``, ``results``, and ``modules`` keys, or ``None`` if
            no matching scan exists.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                return None

            results_row = conn.execute(
                "SELECT data FROM results WHERE scan_id = ?", (scan_id,)
            ).fetchone()

            modules_rows = conn.execute(
                "SELECT name, status FROM modules WHERE scan_id = ?", (scan_id,)
            ).fetchall()

        return {
            "id": row["id"],
            "domain": row["domain"],
            "config": json.loads(row["config"]),
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "results": json.loads(results_row["data"]) if results_row else {},
            "modules": [{"name": m["name"], "status": m["status"]} for m in modules_rows],
        }

    def list_scans(self) -> List[Dict[str, Any]]:
        """Return a summary list of all stored scans.

        Returns:
            A list of dicts with ``id``, ``domain``, ``started_at``, and
            ``finished_at`` keys, ordered by ``started_at`` descending.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, domain, started_at, finished_at FROM scans ORDER BY started_at DESC, id DESC"
            ).fetchall()

        return [
            {
                "id": row["id"],
                "domain": row["domain"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
            }
            for row in rows
        ]

    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan and all its associated results and modules.

        Args:
            scan_id: The numeric scan identifier.

        Returns:
            ``True`` if a scan was deleted, ``False`` if not found.
        """
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0
