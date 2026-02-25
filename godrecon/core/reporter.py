"""Unified report generation facade for GODRECON.

The :class:`ReportGenerator` wraps the individual reporter classes in
``godrecon/reporting/`` and exposes a single interface for generating HTML,
Markdown, JSON, and CSV reports from scan results.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


class ReportGenerator:
    """High-level facade for generating scan reports in multiple formats.

    Delegates to the format-specific reporters in ``godrecon.reporting``.

    Example::

        gen = ReportGenerator()
        gen.generate_json(scan_results, "output/report.json")
        gen.generate_html(scan_results, "output/report.html")
        gen.generate_markdown(scan_results, "output/report.md")
        gen.generate_csv(scan_results, "output/findings.csv")
    """

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def generate_html(self, scan_results: Dict[str, Any], output_path: str) -> Path:
        """Generate a styled self-contained HTML report.

        Includes an executive summary, target information, module results,
        a severity breakdown chart, and an interactive findings table.

        Args:
            scan_results: Scan result dictionary from the scan engine.
            output_path: Destination file path (e.g. ``report.html``).

        Returns:
            :class:`pathlib.Path` to the generated file.
        """
        from godrecon.reporting.html import HTMLReporter
        return HTMLReporter().generate(scan_results, output_path)

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def generate_markdown(self, scan_results: Dict[str, Any], output_path: str) -> Path:
        """Generate a GitHub/GitLab-compatible Markdown report.

        Args:
            scan_results: Scan result dictionary from the scan engine.
            output_path: Destination file path (e.g. ``report.md``).

        Returns:
            :class:`pathlib.Path` to the generated file.
        """
        from godrecon.reporting.markdown_report import MarkdownReporter
        return MarkdownReporter().generate(scan_results, output_path)

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def generate_json(self, scan_results: Dict[str, Any], output_path: str) -> Path:
        """Export scan results as pretty-printed JSON.

        Args:
            scan_results: Scan result dictionary from the scan engine.
            output_path: Destination file path (e.g. ``report.json``).

        Returns:
            :class:`pathlib.Path` to the generated file.
        """
        from godrecon.reporting.json_report import JSONReporter
        return JSONReporter().generate(scan_results, output_path)

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def generate_csv(self, scan_results: Dict[str, Any], output_path: str) -> Path:
        """Export all findings as a CSV file (one row per finding).

        Columns: severity, category, title, description, target, evidence,
        recommendation, module, tags.

        Args:
            scan_results: Scan result dictionary from the scan engine.
            output_path: Destination file path (e.g. ``findings.csv``).

        Returns:
            :class:`pathlib.Path` to the generated file.
        """
        from godrecon.reporting.csv_report import CSVReporter
        return CSVReporter().generate(scan_results, output_path)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def generate(
        self,
        scan_results: Dict[str, Any],
        output_path: str,
        fmt: str = "json",
    ) -> Path:
        """Generate a report in the requested format.

        Args:
            scan_results: Scan result dictionary from the scan engine.
            output_path: Destination file path.
            fmt: One of ``html``, ``md``/``markdown``, ``json``, ``csv``.

        Returns:
            :class:`pathlib.Path` to the generated file.

        Raises:
            ValueError: If *fmt* is not a supported format.
        """
        fmt = fmt.lower().strip()
        if fmt in ("html", "htm"):
            return self.generate_html(scan_results, output_path)
        if fmt in ("md", "markdown"):
            return self.generate_markdown(scan_results, output_path)
        if fmt == "json":
            return self.generate_json(scan_results, output_path)
        if fmt == "csv":
            return self.generate_csv(scan_results, output_path)
        raise ValueError(
            f"Unsupported report format: {fmt!r}. "
            "Choose from: html, md, json, csv."
        )
