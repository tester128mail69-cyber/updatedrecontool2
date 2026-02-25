"""P2 — Sensitive data exposure detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Sensitive file paths to check
_SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php",
    "/config.php",
    "/database.yml",
    "/config/database.yml",
    "/.htpasswd",
    "/web.config",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/.svn/entries",
    "/.DS_Store",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/.well-known/security.txt",
]

# Patterns indicating sensitive content
_SENSITIVE_PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Password field": r"(?i)(password|passwd|pwd)\s*=\s*['\"]?[^'\"\s]{4,}",
    "Database URL": r"(?i)(mysql|postgres|mongodb|redis)://[^\s\"']+",
    "API Key": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}",
    "Git config": r"\[core\]",
    "DB credentials": r"(?i)(DB_USER|DB_PASS|DATABASE_URL)\s*=",
}


class SensitiveDataDetector:
    """Detects exposed sensitive files and data."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client

    async def scan(self, base_url: str) -> List[Finding]:
        """Check for sensitive file exposure."""
        findings: List[Finding] = []
        base = base_url.rstrip("/")

        for path in _SENSITIVE_PATHS:
            url = base + path
            try:
                resp = await self.http.get(url)
                if not resp:
                    continue
                status = resp.get("status", 0)
                if status not in (200, 206):
                    continue
                body = resp.get("body", "") or ""
                if not body or len(body) < 10:
                    continue

                # Check for sensitive content patterns
                matched_patterns = []
                for pattern_name, pattern in _SENSITIVE_PATTERNS.items():
                    if re.search(pattern, body):
                        matched_patterns.append(pattern_name)

                severity = "high" if matched_patterns else "medium"
                confidence = 0.95 if matched_patterns else 0.7

                finding = Finding(
                    title=f"Sensitive File Exposed — {path}",
                    description=(
                        f"Sensitive file accessible at {url}. "
                        + (f"Contains: {', '.join(matched_patterns)}" if matched_patterns else "")
                    ),
                    severity=severity,
                    confidence=confidence,
                    data={
                        "url": url,
                        "path": path,
                        "status": status,
                        "matched_patterns": matched_patterns,
                        "method": "GET",
                    },
                    tags=["sensitive-data", "p2", severity] + matched_patterns,
                    evidence=f"HTTP {status} response for {path}",
                )
                findings.append(finding)
            except Exception as exc:
                logger.debug("Sensitive data scan error for %s: %s", url, exc)

        return findings
