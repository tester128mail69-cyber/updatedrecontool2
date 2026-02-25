"""P3 — CSRF detector."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# CSRF token field names
_CSRF_FIELD_NAMES = [
    "csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
    "authenticity_token", "_csrf", "CSRFToken", "xsrf_token",
    "__RequestVerificationToken",
]


class CSRFDetector:
    """Detects missing CSRF protections on forms."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client

    async def scan(self, url: str) -> List[Finding]:
        """Check for CSRF protection on forms."""
        findings: List[Finding] = []
        try:
            resp = await self.http.get(url)
            if not resp:
                return findings
            body = resp.get("body", "") or ""
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        except Exception as exc:
            logger.debug("CSRF scan error: %s", exc)
            return findings

        # Find POST forms
        forms = re.findall(
            r"<form[^>]*method\s*=\s*[\"']?post[\"']?[^>]*>(.*?)</form>",
            body, re.I | re.S
        )

        for form_html in forms:
            # Check for CSRF token field
            has_csrf = False
            for name in _CSRF_FIELD_NAMES:
                if re.search(rf'name\s*=\s*["\']?{re.escape(name)}["\']?', form_html, re.I):
                    has_csrf = True
                    break

            if not has_csrf:
                # Also check for SameSite cookie
                cookies_header = headers.get("set-cookie", "")
                has_samesite = "samesite" in cookies_header.lower()

                finding = Finding(
                    title=f"Missing CSRF Protection — {url}",
                    description=(
                        f"A POST form at {url} lacks a CSRF token. "
                        + ("Cookie lacks SameSite attribute." if not has_samesite else "")
                    ),
                    severity="medium",
                    confidence=0.8,
                    data={
                        "url": url,
                        "has_samesite": has_samesite,
                        "method": "GET",
                        "type": "csrf",
                    },
                    tags=["csrf", "p3", "medium"],
                    evidence="POST form found without CSRF token field",
                )
                findings.append(finding)

        return findings
