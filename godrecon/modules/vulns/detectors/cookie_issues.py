"""P4 — Cookie security issues detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


def _parse_cookies(set_cookie_header: str) -> List[dict]:
    """Parse Set-Cookie header(s) into a list of cookie attribute dicts."""
    cookies = []
    # Each cookie is semicolon-separated, multiple Set-Cookie headers
    for raw in set_cookie_header.split("\n"):
        raw = raw.strip()
        if not raw:
            continue
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        name_val = parts[0]
        name = name_val.split("=")[0].strip() if "=" in name_val else name_val

        attrs = {p.lower().split("=")[0].strip() for p in parts[1:]}
        cookies.append({"name": name, "raw": raw, "attrs": attrs})
    return cookies


class CookieIssuesDetector:
    """Checks cookies for missing security flags."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client

    async def scan(self, url: str) -> List[Finding]:
        """Check cookies for security attribute issues."""
        findings: List[Finding] = []
        try:
            resp = await self.http.get(url)
            if not resp:
                return findings
            headers = resp.get("headers") or {}
            # Collect all Set-Cookie headers
            set_cookie = ""
            for k, v in headers.items():
                if k.lower() == "set-cookie":
                    set_cookie += v + "\n"
        except Exception as exc:
            logger.debug("Cookie scan error: %s", exc)
            return findings

        if not set_cookie:
            return findings

        cookies = _parse_cookies(set_cookie)
        for cookie in cookies:
            name = cookie["name"]
            attrs = cookie["attrs"]

            if "secure" not in attrs:
                findings.append(Finding(
                    title=f"Cookie Missing Secure Flag — {name}",
                    description=f"Cookie '{name}' at {url} lacks the Secure flag.",
                    severity="low",
                    confidence=1.0,
                    data={"url": url, "cookie": name, "raw": cookie["raw"], "method": "GET"},
                    tags=["cookie", "p4", "low", "secure-flag"],
                    evidence=f"Set-Cookie: {cookie['raw']}",
                ))

            if "httponly" not in attrs:
                findings.append(Finding(
                    title=f"Cookie Missing HttpOnly Flag — {name}",
                    description=f"Cookie '{name}' at {url} lacks the HttpOnly flag.",
                    severity="low",
                    confidence=1.0,
                    data={"url": url, "cookie": name, "raw": cookie["raw"], "method": "GET"},
                    tags=["cookie", "p4", "low", "httponly-flag"],
                    evidence=f"Set-Cookie: {cookie['raw']}",
                ))

            if "samesite" not in attrs:
                findings.append(Finding(
                    title=f"Cookie Missing SameSite Attribute — {name}",
                    description=f"Cookie '{name}' at {url} lacks the SameSite attribute.",
                    severity="low",
                    confidence=1.0,
                    data={"url": url, "cookie": name, "raw": cookie["raw"], "method": "GET"},
                    tags=["cookie", "p4", "low", "samesite"],
                    evidence=f"Set-Cookie: {cookie['raw']}",
                ))

        return findings
