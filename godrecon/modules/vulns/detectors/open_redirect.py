"""P2 — Open Redirect detector."""

from __future__ import annotations

from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Common redirect parameter names
_REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "goto", "dest", "destination",
    "redir", "redirect_uri", "redirect_url", "return_url", "return_to",
    "target", "link", "to", "from", "back", "forward",
]

_TEST_URLS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/path",
]


class OpenRedirectDetector:
    """Detects open redirect vulnerabilities."""

    def __init__(self, http_client: Any, max_payloads: int = 5) -> None:
        self.http = http_client
        self.max_payloads = max_payloads

    async def scan(self, url: str, params: List[str]) -> List[Finding]:
        """Test URL parameters for open redirect."""
        findings: List[Finding] = []

        # Check discovered params + common redirect params
        test_params = list(set(params + _REDIRECT_PARAMS))

        for param in test_params:
            for redirect_url in _TEST_URLS[: self.max_payloads]:
                try:
                    resp = await self.http.get(
                        url,
                        params={param: redirect_url},
                        allow_redirects=False,
                    )
                    if not resp:
                        continue
                    status = resp.get("status", 0)
                    if status in (301, 302, 303, 307, 308):
                        headers = resp.get("headers") or {}
                        location = headers.get("location", "") or headers.get("Location", "")
                        if location.startswith("https://evil.com") or location.startswith("//evil.com"):
                            finding = Finding(
                                title=f"Open Redirect — {url}",
                                description=(
                                    f"Parameter '{param}' redirects to attacker-controlled URL. "
                                    f"Location: {location}"
                                ),
                                severity="medium",
                                confidence=0.95,
                                data={
                                    "url": url,
                                    "param": param,
                                    "payload": redirect_url,
                                    "location": location,
                                    "status": status,
                                    "method": "GET",
                                },
                                tags=["open-redirect", "p2", "medium"],
                                evidence=f"HTTP {status} redirect to {location}",
                            )
                            findings.append(finding)
                            break
                except Exception as exc:
                    logger.debug("Open redirect scan error: %s", exc)

        return findings
