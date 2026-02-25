"""OutputManager — organized per-target scan output directories.

Creates and manages structured output folders for each scanned target,
writes results atomically, and tracks scan metadata.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# Sub-folder names within each target directory
_SUBDIRS = [
    "subdomains",
    "urls",
    "vulnerabilities",
    "secrets",
    "dns",
    "ssl",
    "tech",
    "cloud",
    "screenshots",
    "reports",
]


class OutputManager:
    """Manages structured output directories for GODRECON scans.

    Usage::

        om = OutputManager(base_dir="./output")
        scan_dir = om.init_scan("example.com", scan_id="abc123", modules=["subdomains","ssl"])
        om.write_text("example.com", "subdomains/all_subdomains.txt", "sub1.example.com\\n")
        om.write_json("example.com", "dns/dns_records.json", {"A": ["1.2.3.4"]})
        om.finish_scan("example.com", "abc123", status="completed")
    """

    def __init__(self, base_dir: str = "./output") -> None:
        self.base_dir = Path(base_dir).resolve()

    # ------------------------------------------------------------------
    # Directory helpers
    # ------------------------------------------------------------------

    def target_dir(self, target: str) -> Path:
        """Return the output directory for *target* (creates it if needed)."""
        safe = _safe_name(target)
        d = self.base_dir / safe
        d.mkdir(parents=True, exist_ok=True)
        for sub in _SUBDIRS:
            (d / sub).mkdir(exist_ok=True)
        return d

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def init_scan(
        self,
        target: str,
        scan_id: Optional[str] = None,
        modules: Optional[List[str]] = None,
    ) -> Path:
        """Initialise a new scan for *target*.

        Creates the directory tree and writes an initial
        ``scan_metadata.json``.  Returns the target directory path.
        """
        d = self.target_dir(target)
        if scan_id is None:
            scan_id = str(uuid.uuid4())
        metadata: Dict[str, Any] = {
            "scan_id": scan_id,
            "target": target,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "end_time": None,
            "status": "running",
            "modules_run": modules or [],
            "modules_completed": [],
        }
        self._write_json_atomic(d / "scan_metadata.json", metadata)
        return d

    def finish_scan(self, target: str, scan_id: str, status: str = "completed") -> None:
        """Mark a scan as finished and update ``scan_metadata.json``."""
        d = self.target_dir(target)
        meta_path = d / "scan_metadata.json"
        metadata = self._read_json(meta_path) or {}
        metadata["scan_id"] = scan_id
        metadata["target"] = target
        metadata["end_time"] = datetime.now(timezone.utc).isoformat()
        metadata["status"] = status
        self._write_json_atomic(meta_path, metadata)

    def mark_module_complete(self, target: str, module: str) -> None:
        """Record that *module* has completed for *target*."""
        d = self.target_dir(target)
        meta_path = d / "scan_metadata.json"
        metadata = self._read_json(meta_path) or {}
        completed: List[str] = metadata.get("modules_completed", [])
        if module not in completed:
            completed.append(module)
        metadata["modules_completed"] = completed
        self._write_json_atomic(meta_path, metadata)

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    def write_text(self, target: str, rel_path: str, content: str) -> Path:
        """Write *content* (UTF-8 text) to ``<target_dir>/<rel_path>`` atomically."""
        dest = self.target_dir(target) / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        self._write_text_atomic(dest, content)
        return dest

    def write_json(self, target: str, rel_path: str, data: Any) -> Path:
        """Serialise *data* to JSON and write to ``<target_dir>/<rel_path>`` atomically."""
        dest = self.target_dir(target) / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(dest, data)
        return dest

    def append_text(self, target: str, rel_path: str, line: str) -> Path:
        """Append *line* (plus newline) to a text file."""
        dest = self.target_dir(target) / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("a", encoding="utf-8") as fh:
            fh.write(line.rstrip("\n") + "\n")
        return dest

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def read_text(self, target: str, rel_path: str) -> Optional[str]:
        """Read a text file; returns *None* if it does not exist."""
        p = self.target_dir(target) / rel_path
        if not p.is_file():
            return None
        return p.read_text(encoding="utf-8")

    def read_json(self, target: str, rel_path: str) -> Any:
        """Read and parse a JSON file; returns *None* if it does not exist."""
        p = self.target_dir(target) / rel_path
        return self._read_json(p)

    # ------------------------------------------------------------------
    # Directory listing
    # ------------------------------------------------------------------

    def list_targets(self) -> List[Dict[str, Any]]:
        """Return summary info for all targets that have an output directory."""
        if not self.base_dir.is_dir():
            return []
        results: List[Dict[str, Any]] = []
        for child in sorted(self.base_dir.iterdir()):
            if not child.is_dir():
                continue
            meta = self._read_json(child / "scan_metadata.json") or {}
            results.append(
                {
                    "target": meta.get("target", child.name),
                    "dir": child.name,
                    "scan_id": meta.get("scan_id"),
                    "status": meta.get("status", "unknown"),
                    "start_time": meta.get("start_time"),
                    "end_time": meta.get("end_time"),
                    "modules_completed": meta.get("modules_completed", []),
                }
            )
        return results

    def list_files(self, target: str) -> List[Dict[str, Any]]:
        """Return a recursive list of files under *target*'s output directory."""
        d = self.base_dir / _safe_name(target)
        if not d.is_dir():
            return []
        entries: List[Dict[str, Any]] = []
        for p in sorted(d.rglob("*")):
            if p.is_file():
                rel = p.relative_to(d)
                stat = p.stat()
                entries.append(
                    {
                        "path": str(rel),
                        "name": p.name,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    }
                )
        return entries

    def get_file_path(self, target: str, rel_path: str) -> Optional[Path]:
        """Return the absolute path for a file, or *None* if it doesn't exist.

        Raises ``ValueError`` if the path would escape the target directory
        (path traversal guard).
        """
        d = self.base_dir / _safe_name(target)
        candidate = (d / rel_path).resolve()
        if not str(candidate).startswith(str(d.resolve())):
            raise ValueError("Path traversal detected")
        if candidate.is_file():
            return candidate
        return None

    # ------------------------------------------------------------------
    # Convenience module writers
    # ------------------------------------------------------------------

    def write_subdomains(
        self,
        target: str,
        all_subs: List[str],
        live_subs: Optional[List[str]] = None,
        resolved: Optional[Dict[str, str]] = None,
    ) -> None:
        """Write subdomain output files."""
        self.write_text(target, "subdomains/all_subdomains.txt", "\n".join(all_subs))
        if live_subs is not None:
            self.write_text(target, "subdomains/live_subdomains.txt", "\n".join(live_subs))
        if resolved is not None:
            self.write_json(target, "subdomains/resolved.json", resolved)
        self.mark_module_complete(target, "subdomains")

    def write_urls(
        self,
        target: str,
        wayback: Optional[List[str]] = None,
        crawled: Optional[List[str]] = None,
        parameterized: Optional[List[str]] = None,
    ) -> None:
        """Write URL output files."""
        if wayback is not None:
            self.write_text(target, "urls/wayback_urls.txt", "\n".join(wayback))
        if crawled is not None:
            self.write_text(target, "urls/crawled_urls.txt", "\n".join(crawled))
        if parameterized is not None:
            self.write_text(target, "urls/parameterized_urls.txt", "\n".join(parameterized))
        self.mark_module_complete(target, "urls")

    def write_vulnerabilities(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        vuln_type: Optional[str] = None,
    ) -> None:
        """Write vulnerability output files.

        *vuln_type* can be ``"xss"``, ``"sqli"``, ``"ssrf"``, ``"nuclei"``
        etc.  All findings are also appended to ``all_vulnerabilities.json``.
        """
        if vuln_type:
            self.write_json(target, f"vulnerabilities/{vuln_type}.json", findings)
        # Merge into all_vulnerabilities.json
        existing: List[Any] = self.read_json(target, "vulnerabilities/all_vulnerabilities.json") or []
        merged = existing + findings
        self.write_json(target, "vulnerabilities/all_vulnerabilities.json", merged)
        self.mark_module_complete(target, vuln_type or "vulnerabilities")

    def write_secrets(
        self,
        target: str,
        secrets: List[Dict[str, Any]],
        secret_type: str = "exposed_secrets",
    ) -> None:
        """Write secrets output."""
        self.write_json(target, f"secrets/{secret_type}.json", secrets)
        self.mark_module_complete(target, "secrets")

    def write_dns(self, target: str, records: Dict[str, Any]) -> None:
        self.write_json(target, "dns/dns_records.json", records)
        self.mark_module_complete(target, "dns")

    def write_ssl(self, target: str, data: Dict[str, Any]) -> None:
        self.write_json(target, "ssl/ssl_analysis.json", data)
        self.mark_module_complete(target, "ssl")

    def write_tech(self, target: str, data: Dict[str, Any]) -> None:
        self.write_json(target, "tech/technologies.json", data)
        self.mark_module_complete(target, "tech")

    def write_cloud(self, target: str, data: Any) -> None:
        self.write_json(target, "cloud/cloud_misconfig.json", data)
        self.mark_module_complete(target, "cloud")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _write_text_atomic(dest: Path, content: str) -> None:
        dir_ = dest.parent
        fd, tmp = tempfile.mkstemp(dir=str(dir_), prefix=".tmp_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.replace(tmp, str(dest))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def _write_json_atomic(dest: Path, data: Any) -> None:
        dir_ = dest.parent
        dir_.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(dir_), prefix=".tmp_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, str(dest))

    @staticmethod
    def _read_json(path: Path) -> Any:
        if not path.is_file():
            return None
        try:
            with path.open(encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None


def _safe_name(target: str) -> str:
    """Convert a domain / IP to a filesystem-safe directory name."""
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    # Keep only alphanumeric, dots, dashes, underscores
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    return "".join(c if c in allowed else "_" for c in safe)


# Module-level singleton – lazily initialised by the application.
_default_manager: Optional[OutputManager] = None


def get_output_manager(base_dir: Optional[str] = None) -> OutputManager:
    """Return the process-wide OutputManager, creating it if necessary."""
    global _default_manager
    if _default_manager is None:
        if base_dir is None:
            try:
                from godrecon.core.config import load_config
                cfg = load_config()
                base_dir = getattr(cfg, "output_dir", None) or "./output"
            except Exception:
                base_dir = "./output"
        _default_manager = OutputManager(base_dir=base_dir)
    return _default_manager
