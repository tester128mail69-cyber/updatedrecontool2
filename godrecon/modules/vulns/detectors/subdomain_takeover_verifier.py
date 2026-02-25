"""P1 — Subdomain takeover verifier."""

from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Optional

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Service fingerprints for takeover detection
# Format: {pattern_in_response: (service_name, poc_instructions)}
_TAKEOVER_FINGERPRINTS: Dict[str, tuple] = {
    "There isn't a GitHub Pages site here": (
        "GitHub Pages", "Claim the repository and create a gh-pages branch"
    ),
    "herokucdn.com/error-pages/no-such-app.html": (
        "Heroku", "Create a Heroku app with the matching custom domain"
    ),
    "NoSuchBucket": (
        "AWS S3", "Create an S3 bucket with the matching subdomain name"
    ),
    "The specified bucket does not exist": (
        "AWS S3", "Create an S3 bucket with the matching subdomain name"
    ),
    "404 Not Found": (
        "Generic 404", "Service returned 404 — may be claimable"
    ),
    "This domain is not configured": (
        "Unclaimed Domain", "Domain configuration missing on target service"
    ),
    "Fastly error: unknown domain": (
        "Fastly", "Claim the Fastly service with this domain"
    ),
    "You're Almost There": (
        "Shopify", "Create a Shopify store with this domain"
    ),
    "No settings were found for this company": (
        "HubSpot", "Claim HubSpot portal for this domain"
    ),
    "is not a registered InCloud YouTrack": (
        "JetBrains YouTrack", "Register a YouTrack instance"
    ),
    "Unrecognized domain": (
        "Desk.com", "Claim the Desk.com account for this domain"
    ),
    "NXDOMAIN": (
        "NXDOMAIN", "DNS CNAME points to a non-existent domain — high probability of takeover"
    ),
}


class SubdomainTakeoverVerifier:
    """Verifies subdomain takeover candidates."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client

    async def verify(self, subdomain: str, cname_target: Optional[str] = None) -> List[Finding]:
        """Verify if a subdomain is vulnerable to takeover."""
        findings: List[Finding] = []

        # Check if CNAME target resolves (NXDOMAIN = vulnerable)
        if cname_target:
            try:
                loop_resolved = socket.gethostbyname(cname_target)
            except socket.gaierror:
                # NXDOMAIN — high confidence takeover
                finding = Finding(
                    title=f"Subdomain Takeover — {subdomain}",
                    description=(
                        f"Subdomain {subdomain} has CNAME pointing to {cname_target} "
                        f"which does not resolve (NXDOMAIN). This subdomain can likely be claimed."
                    ),
                    severity="critical",
                    confidence=0.95,
                    data={
                        "subdomain": subdomain,
                        "cname_target": cname_target,
                        "type": "nxdomain",
                    },
                    tags=["takeover", "p1", "critical", "nxdomain"],
                    evidence=f"CNAME {cname_target} returns NXDOMAIN",
                )
                finding.curl_command = f"curl -sk https://{subdomain}/"
                finding.reproduction_steps = [
                    f"1. Confirm: dig {subdomain} CNAME",
                    f"2. Verify NXDOMAIN: dig {cname_target}",
                    f"3. Claim the service at {cname_target}",
                    f"4. Serve content from the claimed service",
                ]
                findings.append(finding)
                return findings

        # HTTP fingerprint check
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}/"
            try:
                resp = await self.http.get(url, allow_redirects=False)
                if not resp:
                    continue
                body = resp.get("body", "") or ""
                status = resp.get("status", 0)

                for fingerprint, (service, poc) in _TAKEOVER_FINGERPRINTS.items():
                    if fingerprint in body or (fingerprint == "NXDOMAIN" and status == 0):
                        finding = Finding(
                            title=f"Subdomain Takeover ({service}) — {subdomain}",
                            description=(
                                f"Subdomain {subdomain} appears vulnerable to takeover via {service}. "
                                f"PoC: {poc}"
                            ),
                            severity="critical",
                            confidence=0.9,
                            data={
                                "subdomain": subdomain,
                                "cname_target": cname_target,
                                "service": service,
                                "fingerprint": fingerprint,
                                "url": url,
                                "method": "GET",
                            },
                            tags=["takeover", "p1", "critical", service.lower().replace(" ", "-")],
                            evidence=f"Service fingerprint '{fingerprint}' found in response",
                        )
                        finding.curl_command = f"curl -sk {url}"
                        finding.reproduction_steps = [
                            f"1. Visit {url}",
                            f"2. Observe response: '{fingerprint}'",
                            f"3. PoC: {poc}",
                        ]
                        findings.append(finding)
                        return findings
                break
            except Exception as exc:
                logger.debug("Takeover verify error for %s: %s", subdomain, exc)

        return findings
