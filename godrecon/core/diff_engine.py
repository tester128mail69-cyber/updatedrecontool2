"""Scan diff engine for GODRECON.

Compares two scan results loaded from the database or provided directly,
highlighting differences in subdomains, ports, vulnerabilities, technologies,
HTTP headers, and endpoints.

Produces a structured :class:`ScanDiffReport` that can be serialised to JSON
or rendered as human-readable text.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from godrecon.core.database import ScanDatabase


# ---------------------------------------------------------------------------
# Report data classes
# ---------------------------------------------------------------------------


@dataclass
class DiffSection:
    """Added / removed / changed items within one category.

    Attributes:
        added: Items present in the newer scan but not the older.
        removed: Items present in the older scan but absent from the newer.
        changed: Items whose value changed between scans.  Each element is a
            dict with ``key``, ``old``, and ``new`` keys.
    """

    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    changed: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """Return ``True`` if any differences exist in this section."""
        return bool(self.added or self.removed or self.changed)


@dataclass
class ScanDiffReport:
    """Structured diff report between two scan results.

    Attributes:
        scan1_id: Database ID of the earlier (baseline) scan.
        scan2_id: Database ID of the newer scan.
        scan1_domain: Domain string for the baseline scan.
        scan2_domain: Domain string for the newer scan.
        scan1_time: Unix timestamp when the baseline scan finished.
        scan2_time: Unix timestamp when the newer scan finished.
        subdomains: Subdomain differences.
        ports: Open port differences.
        vulnerabilities: Vulnerability / finding differences.
        technologies: Detected technology differences.
        headers: HTTP header differences.
        endpoints: Crawled endpoint differences.
    """

    scan1_id: Optional[int]
    scan2_id: Optional[int]
    scan1_domain: str
    scan2_domain: str
    scan1_time: Optional[int]
    scan2_time: Optional[int]
    subdomains: DiffSection = field(default_factory=DiffSection)
    ports: DiffSection = field(default_factory=DiffSection)
    vulnerabilities: DiffSection = field(default_factory=DiffSection)
    technologies: DiffSection = field(default_factory=DiffSection)
    headers: DiffSection = field(default_factory=DiffSection)
    endpoints: DiffSection = field(default_factory=DiffSection)

    @property
    def has_changes(self) -> bool:
        """Return ``True`` if any section has detected differences."""
        return any(
            s.has_changes
            for s in (
                self.subdomains,
                self.ports,
                self.vulnerabilities,
                self.technologies,
                self.headers,
                self.endpoints,
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the report to a plain dictionary."""

        def _section(s: DiffSection) -> Dict[str, Any]:
            return {"added": s.added, "removed": s.removed, "changed": s.changed}

        return {
            "scan1_id": self.scan1_id,
            "scan2_id": self.scan2_id,
            "scan1_domain": self.scan1_domain,
            "scan2_domain": self.scan2_domain,
            "scan1_time": self.scan1_time,
            "scan2_time": self.scan2_time,
            "subdomains": _section(self.subdomains),
            "ports": _section(self.ports),
            "vulnerabilities": _section(self.vulnerabilities),
            "technologies": _section(self.technologies),
            "headers": _section(self.headers),
            "endpoints": _section(self.endpoints),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialise the report to a JSON string.

        Args:
            indent: JSON indentation level.

        Returns:
            Formatted JSON string.
        """
        return json.dumps(self.to_dict(), indent=indent)

    def to_text(self) -> str:
        """Render the report as a human-readable plain-text string.

        Returns:
            Multi-line string suitable for printing to a terminal.
        """
        lines: List[str] = []
        sep = "=" * 60
        lines.append(sep)
        lines.append("GODRECON Scan Diff Report")
        lines.append(sep)
        lines.append(f"Scan 1: #{self.scan1_id}  domain={self.scan1_domain}")
        lines.append(f"Scan 2: #{self.scan2_id}  domain={self.scan2_domain}")

        if not self.has_changes:
            lines.append("\nNo differences detected between scans.")
            return "\n".join(lines)

        def _fmt_section(name: str, section: DiffSection) -> None:
            if not section.has_changes:
                return
            lines.append(f"\n[{name}]")
            for item in section.added:
                lines.append(f"  + {item}")
            for item in section.removed:
                lines.append(f"  - {item}")
            for item in section.changed:
                key = item.get("key", "")
                old = item.get("old", "")
                new = item.get("new", "")
                lines.append(f"  ~ {key}: {old!r} -> {new!r}")

        _fmt_section("Subdomains", self.subdomains)
        _fmt_section("Ports", self.ports)
        _fmt_section("Vulnerabilities", self.vulnerabilities)
        _fmt_section("Technologies", self.technologies)
        _fmt_section("HTTP Headers", self.headers)
        _fmt_section("Endpoints", self.endpoints)

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _get(d: Any, *keys: str, default: Any = None) -> Any:
    """Safely navigate a nested dict, returning *default* on any miss."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur


def _extract_subdomains(results: Dict[str, Any]) -> Set[str]:
    """Extract the set of discovered subdomains from a results dict."""
    subs: Set[str] = set()
    sub_result = results.get("subdomains", {})
    if isinstance(sub_result, dict):
        data = sub_result.get("data", sub_result)
        if isinstance(data, dict):
            for s in data.get("subdomains", []):
                subs.add(str(s))
        elif isinstance(data, list):
            for s in data:
                subs.add(str(s))
    elif isinstance(sub_result, list):
        for s in sub_result:
            subs.add(str(s))
    return subs


def _extract_ports(results: Dict[str, Any]) -> Set[str]:
    """Extract open ports as ``'host:port'`` strings from a results dict."""
    ports: Set[str] = set()
    port_result = results.get("ports", {})
    if isinstance(port_result, dict):
        data = port_result.get("data", port_result)
        if isinstance(data, dict):
            for host, host_data in data.items():
                if host in ("data",):
                    continue
                if isinstance(host_data, dict):
                    for p in host_data.get("open_ports", []):
                        ports.add(f"{host}:{p}")
                elif isinstance(host_data, list):
                    for p in host_data:
                        ports.add(f"{host}:{p}")
        elif isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    host = entry.get("host", "")
                    p = entry.get("port", "")
                    if host and p:
                        ports.add(f"{host}:{p}")
                elif isinstance(entry, str):
                    ports.add(entry)
    return ports


def _extract_vulns(results: Dict[str, Any]) -> Set[str]:
    """Extract vulnerability identifiers from all module findings."""
    vulns: Set[str] = set()
    for module_name, module_result in results.items():
        if not isinstance(module_result, dict):
            continue
        findings = module_result.get("findings", [])
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict):
                    title = str(f.get("title", f.get("description", "")))
                    severity = str(f.get("severity", "info")).lower()
                    key = f"{severity}|{module_name}|{title}"
                    vulns.add(key)
    return vulns


def _extract_technologies(results: Dict[str, Any]) -> Set[str]:
    """Extract detected technology names from a results dict."""
    techs: Set[str] = set()
    for key in ("technologies", "tech", "tech_stack", "waf"):
        tech_result = results.get(key, {})
        if isinstance(tech_result, dict):
            data = tech_result.get("data", tech_result)
            if isinstance(data, dict):
                for name in data.get("technologies", data.get("detected", [])):
                    techs.add(str(name))
            elif isinstance(data, list):
                for t in data:
                    techs.add(str(t))
        elif isinstance(tech_result, list):
            for t in tech_result:
                techs.add(str(t))
    return techs


def _extract_headers(results: Dict[str, Any]) -> Dict[str, str]:
    """Extract HTTP response headers as a name→value mapping."""
    headers: Dict[str, str] = {}
    for key in ("headers", "http_headers", "web"):
        h_result = results.get(key, {})
        if isinstance(h_result, dict):
            data = h_result.get("data", h_result)
            if isinstance(data, dict):
                raw = data.get("headers", data)
                if isinstance(raw, dict):
                    for name, value in raw.items():
                        headers[str(name).lower()] = str(value)
    return headers


def _extract_endpoints(results: Dict[str, Any]) -> Set[str]:
    """Extract crawled endpoint URLs from a results dict."""
    endpoints: Set[str] = set()
    for key in ("crawl", "endpoints", "spider", "urls"):
        ep_result = results.get(key, {})
        if isinstance(ep_result, dict):
            data = ep_result.get("data", ep_result)
            if isinstance(data, dict):
                for url in data.get("endpoints", data.get("urls", [])):
                    endpoints.add(str(url))
            elif isinstance(data, list):
                for url in data:
                    endpoints.add(str(url))
        elif isinstance(ep_result, list):
            for url in ep_result:
                endpoints.add(str(url))
    return endpoints


# ---------------------------------------------------------------------------
# Main engine class
# ---------------------------------------------------------------------------


class ScanDiffEngine:
    """Compares two scan results and produces a :class:`ScanDiffReport`.

    Scan data can be loaded directly from the :class:`ScanDatabase` by
    numeric scan ID, or the two most-recent scans for a domain can be
    compared with :meth:`diff_latest`.

    Args:
        db: An existing :class:`ScanDatabase` instance.  If ``None`` a new
            instance is created using *db_path* (or the default path).
        db_path: Optional path to the SQLite database file.

    Example::

        engine = ScanDiffEngine()
        report = engine.diff_by_ids(1, 2)
        print(report.to_text())

        report = engine.diff_latest("example.com")
        print(report.to_json())
    """

    def __init__(
        self,
        db: Optional[ScanDatabase] = None,
        db_path: Optional[str] = None,
    ) -> None:
        self.db = db if db is not None else ScanDatabase(db_path=db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def diff_by_ids(self, scan_id_1: int, scan_id_2: int) -> ScanDiffReport:
        """Compare two scans by their database IDs.

        Args:
            scan_id_1: ID of the baseline (older) scan.
            scan_id_2: ID of the newer scan to compare against.

        Returns:
            Populated :class:`ScanDiffReport`.

        Raises:
            ValueError: If either scan ID is not found in the database.
        """
        scan1 = self.db.get_scan(scan_id_1)
        if scan1 is None:
            raise ValueError(f"Scan #{scan_id_1} not found in database")
        scan2 = self.db.get_scan(scan_id_2)
        if scan2 is None:
            raise ValueError(f"Scan #{scan_id_2} not found in database")
        return self._diff(scan1, scan2)

    def diff_latest(self, domain: str) -> ScanDiffReport:
        """Compare the two most-recent scans for *domain*.

        Args:
            domain: The target domain to look up in the database.

        Returns:
            Populated :class:`ScanDiffReport`.

        Raises:
            ValueError: If fewer than two scans exist for *domain*.
        """
        all_scans = self.db.list_scans()
        domain_scans = [s for s in all_scans if s["domain"] == domain]
        if len(domain_scans) < 2:
            raise ValueError(
                f"Need at least 2 scans for domain {domain!r}, "
                f"found {len(domain_scans)}"
            )
        # list_scans returns newest-first; compare [1] (older) vs [0] (newer)
        scan1 = self.db.get_scan(domain_scans[1]["id"])
        scan2 = self.db.get_scan(domain_scans[0]["id"])
        if scan1 is None or scan2 is None:  # should not happen
            raise ValueError("Failed to load scan data from database")
        return self._diff(scan1, scan2)

    def diff(
        self,
        scan1: Dict[str, Any],
        scan2: Dict[str, Any],
    ) -> ScanDiffReport:
        """Compare two raw scan dicts (e.g. loaded from JSON files).

        The dicts should have a ``"results"`` key whose value is the
        module-name → result-data mapping.  The ``"id"``, ``"domain"``,
        and ``"finished_at"`` keys are used for metadata when present.

        Args:
            scan1: Baseline scan data dict.
            scan2: Newer scan data dict to compare against.

        Returns:
            Populated :class:`ScanDiffReport`.
        """
        return self._diff(scan1, scan2)

    # ------------------------------------------------------------------
    # Internal implementation
    # ------------------------------------------------------------------

    def _diff(
        self,
        scan1: Dict[str, Any],
        scan2: Dict[str, Any],
    ) -> ScanDiffReport:
        r1: Dict[str, Any] = scan1.get("results", {})
        r2: Dict[str, Any] = scan2.get("results", {})

        report = ScanDiffReport(
            scan1_id=scan1.get("id"),
            scan2_id=scan2.get("id"),
            scan1_domain=scan1.get("domain", ""),
            scan2_domain=scan2.get("domain", ""),
            scan1_time=scan1.get("finished_at"),
            scan2_time=scan2.get("finished_at"),
        )

        report.subdomains = self._diff_sets(
            _extract_subdomains(r1), _extract_subdomains(r2)
        )
        report.ports = self._diff_sets(_extract_ports(r1), _extract_ports(r2))
        report.vulnerabilities = self._diff_sets(
            _extract_vulns(r1), _extract_vulns(r2)
        )
        report.technologies = self._diff_sets(
            _extract_technologies(r1), _extract_technologies(r2)
        )
        report.headers = self._diff_headers(
            _extract_headers(r1), _extract_headers(r2)
        )
        report.endpoints = self._diff_sets(
            _extract_endpoints(r1), _extract_endpoints(r2)
        )

        return report

    @staticmethod
    def _diff_sets(old: Set[str], new: Set[str]) -> DiffSection:
        return DiffSection(
            added=sorted(new - old),
            removed=sorted(old - new),
        )

    @staticmethod
    def _diff_headers(
        old: Dict[str, str],
        new: Dict[str, str],
    ) -> DiffSection:
        old_keys = set(old)
        new_keys = set(new)
        added = sorted(
            f"{k}: {new[k]}" for k in (new_keys - old_keys)
        )
        removed = sorted(
            f"{k}: {old[k]}" for k in (old_keys - new_keys)
        )
        changed = [
            {"key": k, "old": old[k], "new": new[k]}
            for k in sorted(old_keys & new_keys)
            if old[k] != new[k]
        ]
        return DiffSection(added=added, removed=removed, changed=changed)
