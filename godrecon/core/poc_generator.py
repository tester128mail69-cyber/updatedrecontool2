"""PoC (Proof of Concept) generator for GODRECON findings."""

from __future__ import annotations

import shlex
from typing import Any, Dict, List, Optional

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# CVSS base scores by vulnerability type and severity
_CVSS_ESTIMATES: Dict[str, Dict[str, float]] = {
    "sqli": {"critical": 9.8, "high": 8.5, "medium": 6.5, "low": 4.0, "info": 2.0},
    "xss": {"critical": 8.8, "high": 7.4, "medium": 6.1, "low": 3.1, "info": 1.5},
    "rce": {"critical": 10.0, "high": 9.0, "medium": 7.5, "low": 5.0, "info": 2.0},
    "ssrf": {"critical": 9.6, "high": 8.6, "medium": 7.2, "low": 4.5, "info": 2.0},
    "open_redirect": {"critical": 6.1, "high": 5.4, "medium": 4.3, "low": 3.1, "info": 1.5},
    "csrf": {"critical": 8.8, "high": 7.4, "medium": 5.4, "low": 3.5, "info": 1.5},
    "idor": {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 1.5},
    "sensitive_data": {"critical": 7.5, "high": 6.5, "medium": 5.0, "low": 3.0, "info": 1.5},
    "cors": {"critical": 8.1, "high": 7.1, "medium": 5.4, "low": 3.1, "info": 1.5},
    "default": {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0},
}

# Bug bounty severity mapping (HackerOne/Bugcrowd)
_BB_SEVERITY: Dict[str, str] = {
    "critical": "P1 — Critical",
    "high": "P2 — High",
    "medium": "P3 — Medium",
    "low": "P4 — Low",
    "info": "P5 — Informational",
}

# Impact descriptions by vulnerability type
_IMPACT_DESCRIPTIONS: Dict[str, str] = {
    "sqli": (
        "SQL Injection allows an attacker to interfere with database queries, "
        "potentially leading to unauthorized data access, authentication bypass, "
        "data manipulation, or full database compromise."
    ),
    "xss": (
        "Cross-Site Scripting allows attackers to inject malicious scripts into "
        "pages viewed by other users, enabling session hijacking, credential theft, "
        "or malicious redirects."
    ),
    "rce": (
        "Remote Code Execution allows an attacker to execute arbitrary commands "
        "on the target server, leading to complete system compromise."
    ),
    "ssrf": (
        "Server-Side Request Forgery allows an attacker to induce the server to "
        "make HTTP requests to internal resources, potentially exposing cloud metadata, "
        "internal services, or enabling further exploitation."
    ),
    "open_redirect": (
        "Open Redirect allows attackers to redirect users from a trusted domain "
        "to a malicious site, facilitating phishing attacks."
    ),
    "csrf": (
        "Cross-Site Request Forgery allows attackers to trick authenticated users "
        "into performing unintended actions without their knowledge."
    ),
    "idor": (
        "Insecure Direct Object Reference allows attackers to access or modify "
        "other users' data by manipulating object identifiers."
    ),
    "sensitive_data": (
        "Sensitive data exposure leaks confidential information such as credentials, "
        "API keys, PII, or internal system details to unauthorized parties."
    ),
    "cors": (
        "CORS misconfiguration allows malicious websites to make cross-origin "
        "requests with user credentials, leading to data theft."
    ),
    "takeover": (
        "Subdomain takeover allows an attacker to claim control of an abandoned "
        "subdomain, enabling phishing, malware distribution, or cookie theft."
    ),
    "default": (
        "This vulnerability may allow unauthorized access, data exposure, or "
        "other security impacts depending on the specific context."
    ),
}


class PoCGenerator:
    """Generates human-readable Proof of Concept for confirmed findings."""

    def generate_curl(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
    ) -> str:
        """Build a curl command reproducing the finding."""
        parts = ["curl", "-sk"]
        if method.upper() != "GET":
            parts += ["-X", method.upper()]

        if headers:
            for k, v in headers.items():
                parts += ["-H", f"{k}: {v}"]

        if proxy:
            parts += ["--proxy", proxy]

        if data:
            encoded = "&".join(f"{k}={v}" for k, v in data.items())
            parts += ["-d", encoded]

        # Append query params to URL
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{qs}" if "?" not in url else f"{url}&{qs}"

        parts.append(shlex.quote(url))
        return " ".join(parts)

    def estimate_cvss(self, vuln_type: str, severity: str) -> float:
        """Estimate CVSS score based on vuln type and severity."""
        severity = severity.lower()
        vuln_type = vuln_type.lower()
        scores = _CVSS_ESTIMATES.get(vuln_type, _CVSS_ESTIMATES["default"])
        return scores.get(severity, scores.get("info", 1.0))

    def get_bug_bounty_severity(self, severity: str) -> str:
        """Map internal severity to HackerOne/Bugcrowd severity label."""
        return _BB_SEVERITY.get(severity.lower(), "P5 — Informational")

    def get_impact(self, vuln_type: str) -> str:
        """Return impact description for a vulnerability type."""
        vuln_type = vuln_type.lower()
        return _IMPACT_DESCRIPTIONS.get(vuln_type, _IMPACT_DESCRIPTIONS["default"])

    def build_reproduction_steps(
        self,
        vuln_type: str,
        url: str,
        param: Optional[str] = None,
        payload: Optional[str] = None,
        extra_steps: Optional[List[str]] = None,
    ) -> List[str]:
        """Build numbered reproduction steps for a finding."""
        steps: List[str] = [f"1. Navigate to {url}"]

        vuln_type = vuln_type.lower()
        step = 2

        if param and payload:
            steps.append(f"{step}. Set parameter '{param}' to: {payload}")
            step += 1

        if vuln_type == "sqli":
            steps.append(f"{step}. Submit the request and observe the response time or error message")
            step += 1
            steps.append(f"{step}. Confirm by using a boolean payload that changes the response content")
        elif vuln_type == "xss":
            steps.append(f"{step}. Submit the form or request with the XSS payload")
            step += 1
            steps.append(f"{step}. Observe the payload reflected unescaped in the response body")
        elif vuln_type == "open_redirect":
            steps.append(f"{step}. Follow the redirect and observe the Location header")
            step += 1
            steps.append(f"{step}. Confirm the browser is redirected to the attacker-controlled domain")
        elif vuln_type == "ssrf":
            steps.append(f"{step}. Observe the response content for internal resource data")
            step += 1
            steps.append(f"{step}. Confirm access to internal metadata endpoint or service")
        elif vuln_type == "cors":
            steps.append(f"{step}. Send request with Origin: https://evil.com header")
            step += 1
            steps.append(f"{step}. Observe Access-Control-Allow-Origin: https://evil.com in response")
        else:
            steps.append(f"{step}. Observe the response for the vulnerability indicator")

        if extra_steps:
            for es in extra_steps:
                step += 1
                steps.append(f"{step}. {es}")

        return steps

    def enrich_finding(self, finding: Any, vuln_type: str = "default") -> Any:
        """Enrich a Finding object with PoC data."""
        url = finding.data.get("url", "")
        method = finding.data.get("method", "GET")
        param = finding.data.get("param")
        payload = finding.data.get("payload")
        headers = finding.data.get("headers")

        # Generate curl command
        params_dict = {param: payload} if param and payload else None
        finding.curl_command = self.generate_curl(
            url=url,
            method=method,
            headers=headers,
            params=params_dict,
        )

        # Raw request (simplified)
        if url:
            finding.raw_request = self._build_raw_request(url, method, params_dict, headers)

        # Reproduction steps
        finding.reproduction_steps = self.build_reproduction_steps(
            vuln_type=vuln_type,
            url=url,
            param=param,
            payload=payload,
        )

        # Impact
        if not finding.impact:
            finding.impact = self.get_impact(vuln_type)

        # CVSS
        if finding.cvss_score is None:
            finding.cvss_score = self.estimate_cvss(vuln_type, finding.severity)

        # Bug bounty severity
        if not finding.bug_bounty_severity:
            finding.bug_bounty_severity = self.get_bug_bounty_severity(finding.severity)

        return finding

    @staticmethod
    def _build_raw_request(
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        """Build a simplified raw HTTP request string."""
        from urllib.parse import urlparse, urlencode
        parsed = urlparse(url)
        path = parsed.path or "/"
        if params:
            path += "?" + urlencode(params)
        host = parsed.netloc or parsed.path

        lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {host}"]
        if headers:
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        lines.append("Connection: close")
        lines.append("")
        return "\r\n".join(lines)
