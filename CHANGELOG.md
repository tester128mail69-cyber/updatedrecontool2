# Changelog

All notable changes to GODRECON are documented here.
All changes by **nothingmch69**.

---

## [Unreleased] — PR #7: README, Docs, Repo Beautification

- Complete README rewrite — premium open-source project quality
- Added CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- Full docs directory: INSTALLATION, USAGE, CLI_REFERENCE, DASHBOARD_GUIDE, API_KEYS_SETUP, SCAN_MODES, ARCHITECTURE, FAQ
- Updated LICENSE copyright to nothingmch69 (2026)
- Updated pyproject.toml author to nothingmch69
- Updated `__author__` in `godrecon/__init__.py`
- CLI banner now shows "by nothingmch69"
- Dashboard footer now shows "GODRECON by nothingmch69"
- Report templates now credit nothingmch69

---

## [0.2.0] — PR #6: Subdomain Supercharger

- Added 8 new subdomain discovery techniques/sources (38+ total)
- DNS brute-force with smart wordlists
- Permutation engine (altdns-style)
- Recursive subdomain enumeration
- AXFR zone transfer attempts
- TLS certificate scraping
- Reverse DNS enumeration
- NOERROR-based enumeration
- Favicon hash matching
- SPF/TXT record mining for subdomain hints
- Total subdomain sources now 38+

---

## [0.1.5] — PR #5: Dashboard UI — 70 Features

- Full web dashboard with 70 features
- 33+ Jinja2 HTML template pages
- 75 routes + 30 API endpoints
- Live scan progress with real-time updates
- Dark/light theme toggle
- Global search (Ctrl+K)
- Kanban-style findings board
- Analytics with charts and trends
- Bug bounty matcher UI
- AI validation panel
- Secrets explorer
- Alert management
- Continuous monitoring dashboard
- Report generation wizard
- Scan diffing view

---

## [0.1.4] — PR #4: 15 Features — Multi-AI, Passive Recon, Cloud Misconfig

- Multi-AI vulnerability validation (OpenAI, Claude, Gemini, Ollama, Pattern-based)
- Passive recon module (Shodan, Censys, SecurityTrails, VirusTotal)
- Cloud misconfiguration scanner (S3, Azure Blob, GCP, Firebase, K8s, Docker)
- Auto vulnerability chaining
- Supply chain analysis module
- Mobile API endpoint extractor (APK decompilation)
- Business logic flaw detection
- Cache poisoning scanner
- Wayback Machine deep mining
- Browser extension analyzer
- Multi-region scanning support
- Bug bounty program auto-matcher
- Smart priority scoring (0–100)
- Auto bug report generator (HackerOne, Bugcrowd, Markdown, PDF)
- Scan diffing engine

---

## [0.1.3] — PR #3: 17 Features — Vuln Detectors, Nuclei, OOB, Auth

- 18 vulnerability detectors (P1–P5): SQLi, RCE, SSRF, XSS, LFI/RFI, XXE, SSTI, IDOR, CSRF, CORS, Open Redirect, Command Injection, Deserialization, JWT attacks, GraphQL injection
- Nuclei integration (8000+ templates)
- Out-of-Band (OOB) detection (blind SSRF, XSS, SQLi, XXE, RCE)
- Authenticated scanning (cookie, token, header injection)
- JS secrets scanner (16 regex patterns + entropy analysis)
- GitHub/GitLab dorking module
- Smart parameter discovery
- WAF detection & bypass (Cloudflare, Akamai, AWS WAF, Sucuri, Imperva, ModSecurity, F5)
- Broken authentication scanner
- Email security (SPF/DKIM/DMARC)
- Bug bounty program detection
- Continuous monitoring with Slack/Discord/Telegram/Webhook alerts
- JSON/HTML/CSV/Markdown/PDF report generation

---

## [0.1.2] — PR #2: Deep Scan Mode, Verification Engine, P1–P4 Detectors

- Deep scan mode (`--deep` flag) — exhaustive scanning, no timeouts
- Cross-validation / verification engine
- P1–P4 vulnerability detectors
- Port scanning (full 65535 or top ports)
- Technology fingerprinting
- SSL/TLS analysis
- DNS intelligence module
- Cloud asset discovery

---

## [0.1.1] — PR #1: Core Overhaul

- Parallel execution engine with async-first architecture
- Circuit breaker pattern for resilient scanning
- Confidence scoring system (0.0–1.0)
- BaseModule abstract class
- Pydantic v2 configuration models
- Rich CLI with progress bars and colored output
- FastAPI REST server
- Continuous monitoring scheduler

---

## [0.1.0] — Initial Release

- Core async scan engine
- Subdomain enumeration (basic sources)
- HTTP probing
- CLI with Typer + Rich
- YAML configuration
- Basic JSON reporting
