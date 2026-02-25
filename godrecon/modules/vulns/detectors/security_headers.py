"""P3 — Security headers checker."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


# (header_name, required, severity_if_missing, check_fn_description)
_HEADER_CHECKS: List[Tuple[str, str, str, Optional[str]]] = [
    ("strict-transport-security", "Strict-Transport-Security", "medium",
     "max-age >= 31536000"),
    ("x-content-type-options", "X-Content-Type-Options", "low", "nosniff"),
    ("x-frame-options", "X-Frame-Options", "medium", "DENY or SAMEORIGIN"),
    ("content-security-policy", "Content-Security-Policy", "medium", None),
    ("referrer-policy", "Referrer-Policy", "low", None),
    ("permissions-policy", "Permissions-Policy", "low", None),
]


class SecurityHeadersDetector:
    """Checks HTTP responses for security header issues."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client

    async def scan(self, url: str) -> List[Finding]:
        """Check security headers for the given URL."""
        findings: List[Finding] = []
        try:
            resp = await self.http.get(url)
            if not resp:
                return findings
            headers: Dict[str, str] = {
                k.lower(): v for k, v in (resp.get("headers") or {}).items()
            }
        except Exception as exc:
            logger.debug("Security headers scan error: %s", exc)
            return findings

        for header_lower, header_display, severity, note in _HEADER_CHECKS:
            if header_lower not in headers:
                findings.append(Finding(
                    title=f"Missing Security Header: {header_display}",
                    description=(
                        f"The response from {url} is missing the {header_display} header. "
                        + (f"Recommended: {note}" if note else "")
                    ),
                    severity=severity,
                    confidence=1.0,
                    data={"url": url, "header": header_display, "method": "GET"},
                    tags=["security-headers", "p3", severity, header_lower],
                    evidence=f"Header '{header_display}' absent from response",
                ))
                continue

            value = headers[header_lower]

            # Enhanced checks
            if header_lower == "strict-transport-security":
                m = re.search(r"max-age=(\d+)", value, re.I)
                if not m or int(m.group(1)) < 31536000:
                    findings.append(Finding(
                        title=f"Weak HSTS Configuration — {url}",
                        description=(
                            f"Strict-Transport-Security max-age should be >= 31536000. "
                            f"Current: {value}"
                        ),
                        severity="low",
                        confidence=1.0,
                        data={"url": url, "header": header_display, "value": value, "method": "GET"},
                        tags=["hsts", "security-headers", "p3", "low"],
                        evidence=f"HSTS max-age too low: {value}",
                    ))

            elif header_lower == "content-security-policy":
                issues = []
                if "unsafe-inline" in value:
                    issues.append("'unsafe-inline'")
                if "unsafe-eval" in value:
                    issues.append("'unsafe-eval'")
                if issues:
                    findings.append(Finding(
                        title=f"Weak CSP Configuration — {url}",
                        description=(
                            f"Content-Security-Policy contains insecure directives: "
                            f"{', '.join(issues)}. Value: {value}"
                        ),
                        severity="medium",
                        confidence=1.0,
                        data={"url": url, "header": header_display, "value": value, "issues": issues, "method": "GET"},
                        tags=["csp", "security-headers", "p3", "medium"],
                        evidence=f"CSP contains {', '.join(issues)}",
                    ))

        return findings
