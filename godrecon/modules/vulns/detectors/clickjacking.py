"""P4 — Clickjacking detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class ClickjackingDetector:
    """Checks if a page can be framed (clickjacking vulnerability)."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client

    async def scan(self, url: str) -> List[Finding]:
        """Check for missing clickjacking protection."""
        findings: List[Finding] = []
        try:
            resp = await self.http.get(url)
            if not resp:
                return findings
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            body = resp.get("body", "") or ""
        except Exception as exc:
            logger.debug("Clickjacking scan error: %s", exc)
            return findings

        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")

        has_xfo = bool(xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN"))
        has_csp_frame_ancestors = bool(
            re.search(r"frame-ancestors", csp, re.I)
        )

        if not has_xfo and not has_csp_frame_ancestors:
            finding = Finding(
                title=f"Clickjacking — Missing Frame Protection — {url}",
                description=(
                    f"Page at {url} lacks both X-Frame-Options and CSP frame-ancestors. "
                    "It can be embedded in an iframe, enabling clickjacking attacks."
                ),
                severity="low",
                confidence=0.9,
                data={
                    "url": url,
                    "x_frame_options": xfo or "(absent)",
                    "csp": csp or "(absent)",
                    "method": "GET",
                },
                tags=["clickjacking", "p4", "low"],
                evidence="No X-Frame-Options or CSP frame-ancestors header found",
            )
            findings.append(finding)

        return findings
