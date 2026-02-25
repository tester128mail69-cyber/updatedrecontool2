"""P3 — CORS misconfiguration detector."""

from __future__ import annotations

from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://target.com.evil.com",
]


class CORSMisconfigDetector:
    """Detects CORS misconfigurations."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client

    async def scan(self, url: str) -> List[Finding]:
        """Test CORS configuration with various origins."""
        findings: List[Finding] = []

        for origin in _TEST_ORIGINS:
            try:
                resp = await self.http.get(
                    url,
                    headers={"Origin": origin},
                )
                if not resp:
                    continue
                headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
                acao = headers.get("access-control-allow-origin", "")
                acac = headers.get("access-control-allow-credentials", "").lower()

                if not acao:
                    continue

                # Critical: ACAO reflects evil origin + ACAC: true
                if (acao == origin or acao == "*") and acac == "true":
                    finding = Finding(
                        title=f"CORS Misconfiguration (Critical) — {url}",
                        description=(
                            f"CORS allows credentials with origin '{acao}'. "
                            f"Access-Control-Allow-Origin: {acao}, "
                            f"Access-Control-Allow-Credentials: true"
                        ),
                        severity="high",
                        confidence=0.95,
                        data={
                            "url": url,
                            "test_origin": origin,
                            "acao": acao,
                            "acac": acac,
                            "method": "GET",
                        },
                        tags=["cors", "p3", "high"],
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                    )
                    findings.append(finding)
                elif acao == origin and origin == "null":
                    finding = Finding(
                        title=f"CORS Allows Null Origin — {url}",
                        description=(
                            f"CORS allows the 'null' origin, which can be exploited "
                            f"from sandboxed iframes."
                        ),
                        severity="medium",
                        confidence=0.9,
                        data={"url": url, "test_origin": origin, "acao": acao, "method": "GET"},
                        tags=["cors", "p3", "medium", "null-origin"],
                        evidence=f"ACAO: null",
                    )
                    findings.append(finding)
                elif acao == origin:
                    finding = Finding(
                        title=f"CORS Reflects Arbitrary Origin — {url}",
                        description=(
                            f"CORS reflects arbitrary origin '{origin}' without "
                            f"credential sharing (lower risk)."
                        ),
                        severity="low",
                        confidence=0.85,
                        data={"url": url, "test_origin": origin, "acao": acao, "method": "GET"},
                        tags=["cors", "p3", "low"],
                        evidence=f"ACAO reflects: {acao}",
                    )
                    findings.append(finding)
            except Exception as exc:
                logger.debug("CORS scan error: %s", exc)

        return findings
