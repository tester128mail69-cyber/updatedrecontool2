"""P4 — Version disclosure detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_VERSION_PATTERNS = {
    "Server Header": (r"Server", r"(?:Apache|nginx|IIS|lighttpd|LiteSpeed)/[\d\.]+"),
    "X-Powered-By": (r"X-Powered-By", r".+"),
    "PHP Version": (r"X-Powered-By", r"PHP/[\d\.]+"),
    "ASP.NET Version": (r"X-AspNet-Version", r".+"),
    "Generator Meta": (None, r'<meta\s+name=["\']?generator["\']?\s+content=["\']?([^"\'>]+)'),
}


class VersionDisclosureDetector:
    """Checks for technology/version disclosure in headers and body."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client

    async def scan(self, url: str) -> List[Finding]:
        """Check for version disclosure."""
        findings: List[Finding] = []
        try:
            resp = await self.http.get(url)
            if not resp:
                return findings
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            body = resp.get("body", "") or ""
        except Exception as exc:
            logger.debug("Version disclosure scan error: %s", exc)
            return findings

        for label, (header_name, pattern) in _VERSION_PATTERNS.items():
            if header_name:
                value = headers.get(header_name.lower(), "")
                if value and re.search(pattern, value, re.I):
                    findings.append(Finding(
                        title=f"Version Disclosure — {label}",
                        description=(
                            f"Server reveals version information via {header_name} header: {value}"
                        ),
                        severity="info",
                        confidence=1.0,
                        data={
                            "url": url,
                            "header": header_name,
                            "value": value,
                            "method": "GET",
                        },
                        tags=["version-disclosure", "p4", "info"],
                        evidence=f"{header_name}: {value}",
                    ))
            else:
                # Body-based check
                m = re.search(pattern, body, re.I)
                if m:
                    findings.append(Finding(
                        title=f"Version Disclosure — {label}",
                        description=f"Page at {url} reveals version via generator meta tag: {m.group(1) if m.lastindex else m.group(0)}",
                        severity="info",
                        confidence=0.9,
                        data={
                            "url": url,
                            "match": m.group(0),
                            "method": "GET",
                        },
                        tags=["version-disclosure", "p4", "info"],
                        evidence=f"Generator meta: {m.group(0)}",
                    ))

        return findings
