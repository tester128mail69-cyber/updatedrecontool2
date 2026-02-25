"""P1 — SQL Injection detector."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Time-based payloads (safe — no destructive queries)
_TIME_PAYLOADS = [
    "' AND SLEEP(5)--",
    "\" AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
]

# Error-based payloads
_ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR ''='",
]

# SQL error patterns
_SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"ORA-[0-9]{4,5}",
    r"Microsoft OLE DB.*SQL",
    r"ODBC SQL Server Driver",
    r"SQLite.*error",
    r"pg_query\(\): Query failed",
    r"ERROR: syntax error at",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"You have an error in your SQL syntax",
    r"supplied argument is not a valid MySQL",
]

_SAFE_DELAY = 5.0
_CONFIRM_DELAY = 3.0


class SQLInjectionDetector:
    """Detects SQL injection vulnerabilities in URL parameters and forms."""

    def __init__(
        self,
        http_client: Any,
        safe_mode: bool = True,
        max_payloads: int = 10,
        timeout: float = 15.0,
    ) -> None:
        self.http = http_client
        self.safe_mode = safe_mode
        self.max_payloads = max_payloads
        self.timeout = timeout

    async def scan(self, url: str, params: List[str]) -> List[Finding]:
        """Scan URL parameters for SQLi."""
        findings: List[Finding] = []
        import re

        for param in params:
            # Error-based detection
            for payload in _ERROR_PAYLOADS[: self.max_payloads]:
                try:
                    resp = await self.http.get(url, params={param: payload})
                    if not resp:
                        continue
                    body = resp.get("body", "") or ""
                    for pattern in _SQL_ERROR_PATTERNS:
                        if re.search(pattern, body, re.I):
                            finding = Finding(
                                title=f"SQL Injection (Error-Based) — {url}",
                                description=f"Parameter '{param}' is vulnerable to error-based SQLi. "
                                            f"Payload: {payload}",
                                severity="critical",
                                confidence=0.9,
                                data={
                                    "url": url,
                                    "param": param,
                                    "payload": payload,
                                    "type": "error-based",
                                    "method": "GET",
                                },
                                tags=["sqli", "p1", "critical", "error-based"],
                                evidence=f"SQL error pattern matched in response body",
                            )
                            findings.append(finding)
                            break
                except Exception as exc:
                    logger.debug("SQLi error-based scan error: %s", exc)

            # Time-based detection (safe mode only uses short delays)
            for payload in _TIME_PAYLOADS[: self.max_payloads]:
                try:
                    start = time.monotonic()
                    resp = await asyncio.wait_for(
                        self.http.get(url, params={param: payload}),
                        timeout=self.timeout,
                    )
                    elapsed = time.monotonic() - start
                    if elapsed >= _SAFE_DELAY * 0.8:
                        finding = Finding(
                            title=f"SQL Injection (Time-Based) — {url}",
                            description=f"Parameter '{param}' is vulnerable to time-based SQLi. "
                                        f"Payload caused {elapsed:.1f}s delay.",
                            severity="critical",
                            confidence=0.95,
                            data={
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "type": "time-based",
                                "delay_observed": elapsed,
                                "method": "GET",
                            },
                            tags=["sqli", "p1", "critical", "time-based"],
                            evidence=f"Response delayed {elapsed:.1f}s with SLEEP payload",
                        )
                        findings.append(finding)
                        break
                except asyncio.TimeoutError:
                    # Timeout itself is evidence of time-based SQLi
                    finding = Finding(
                        title=f"SQL Injection (Time-Based) — {url}",
                        description=f"Parameter '{param}' caused request timeout with SQLi payload.",
                        severity="critical",
                        confidence=0.9,
                        data={
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "type": "time-based",
                            "method": "GET",
                        },
                        tags=["sqli", "p1", "critical", "time-based"],
                        evidence="Request timed out with SLEEP payload",
                    )
                    findings.append(finding)
                except Exception as exc:
                    logger.debug("SQLi time-based scan error: %s", exc)

        return findings
