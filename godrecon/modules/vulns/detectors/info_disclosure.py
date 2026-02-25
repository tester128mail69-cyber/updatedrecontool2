"""P3 — Information disclosure detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_DEBUG_PATHS = [
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug",
    "/debug.php",
    "/server-status",
    "/server-info",
    "/_profiler",
    "/__debug_bar",
    "/actuator",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/info",
    "/actuator/health",
    "/graphql",
    "/.well-known/security.txt",
]

# Patterns indicating debug/info disclosure
_DISCLOSURE_PATTERNS = {
    "PHP Info": r"phpinfo\(\)|PHP Version|php\.ini",
    "Stack Trace": r"Traceback.*File.*line|at [\w\.]+\([\w\.]+\.java:\d+\)",
    "Debug Mode": r"DEBUG\s*=\s*True|debug.*=.*true",
    "SQL Error": r"SQL syntax.*MySQL|ORA-\d{5}|PostgreSQL.*ERROR",
    "Server Info": r"Apache/\d+\.\d+|nginx/\d+\.\d+|IIS/\d+",
    "GraphQL Introspection": r'"__schema"',
    "Framework Error": r"Whoa! Error|Symfony.*Exception|Django.*Error",
}


class InfoDisclosureDetector:
    """Detects information disclosure via debug pages and error messages."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client

    async def scan(self, base_url: str) -> List[Finding]:
        """Check for information disclosure pages."""
        findings: List[Finding] = []
        base = base_url.rstrip("/")

        for path in _DEBUG_PATHS:
            url = base + path
            try:
                resp = await self.http.get(url)
                if not resp:
                    continue
                status = resp.get("status", 0)
                if status not in (200, 206):
                    continue
                body = resp.get("body", "") or ""

                matched = []
                for label, pattern in _DISCLOSURE_PATTERNS.items():
                    if re.search(pattern, body, re.I | re.S):
                        matched.append(label)

                if matched:
                    finding = Finding(
                        title=f"Information Disclosure — {path}",
                        description=(
                            f"Page {url} exposes sensitive information: "
                            f"{', '.join(matched)}"
                        ),
                        severity="medium",
                        confidence=0.9,
                        data={
                            "url": url,
                            "path": path,
                            "matched": matched,
                            "status": status,
                            "method": "GET",
                        },
                        tags=["info-disclosure", "p3", "medium"] + matched,
                        evidence=f"Patterns found: {', '.join(matched)}",
                    )
                    findings.append(finding)
            except Exception as exc:
                logger.debug("Info disclosure scan error for %s: %s", url, exc)

        return findings
