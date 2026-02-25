"""P2 — Cross-Site Scripting (XSS) detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# XSS polyglot payloads
_XSS_PAYLOADS = [
    "<script>alert('GODRECON')</script>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    '"><svg onload=alert(1)>',
    "';alert(1)//",
]

# Marker for reflection detection (won't execute)
_SAFE_MARKER = "GODRECON_XSS_MARKER_12345"


class XSSDetector:
    """Detects reflected XSS in URL parameters."""

    def __init__(
        self,
        http_client: Any,
        safe_mode: bool = True,
        max_payloads: int = 10,
    ) -> None:
        self.http = http_client
        self.safe_mode = safe_mode
        self.max_payloads = max_payloads

    async def scan(self, url: str, params: List[str]) -> List[Finding]:
        """Scan URL parameters for reflected XSS."""
        findings: List[Finding] = []

        for param in params:
            # Use safe marker first to check reflection
            try:
                resp = await self.http.get(url, params={param: _SAFE_MARKER})
                if not resp:
                    continue
                body = resp.get("body", "") or ""
                if _SAFE_MARKER not in body:
                    continue  # Not reflected — skip XSS testing

                # Reflection confirmed; now test with payloads
                for payload in _XSS_PAYLOADS[: self.max_payloads]:
                    try:
                        resp2 = await self.http.get(url, params={param: payload})
                        if not resp2:
                            continue
                        body2 = resp2.get("body", "") or ""

                        # Check for unescaped payload in body
                        if payload in body2:
                            # Determine context — skip if in HTML comment
                            idx = body2.find(payload)
                            prefix = body2[max(0, idx - 200):idx]
                            if re.search(r"<!--", prefix) and not re.search(r"-->", prefix):
                                continue  # In comment — not exploitable

                            finding = Finding(
                                title=f"Reflected XSS — {url}",
                                description=(
                                    f"Parameter '{param}' reflects unsanitized input. "
                                    f"Payload: {payload}"
                                ),
                                severity="high",
                                confidence=0.9,
                                data={
                                    "url": url,
                                    "param": param,
                                    "payload": payload,
                                    "method": "GET",
                                    "type": "reflected",
                                },
                                tags=["xss", "p2", "high", "reflected"],
                                evidence=f"Payload reflected unescaped in response body",
                            )
                            findings.append(finding)
                            break
                    except Exception as exc:
                        logger.debug("XSS payload test error: %s", exc)
            except Exception as exc:
                logger.debug("XSS marker test error: %s", exc)

        return findings
