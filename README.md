<p align="center">
  <!-- Logo placeholder: replace the src with your actual logo path once available -->
  <img src="docs/assets/logo.png" alt="GodRecon Logo" width="300" />
</p>

<h1 align="center">GODRECON</h1>

<p align="center">
<pre>
 ██████╗  ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║  ███╗██║   ██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║██║   ██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝╚██████╔╝██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                          by nothingmch69
</pre>
</p>

[![CI](https://github.com/tester128mail69-cyber/updatedrecontool2/actions/workflows/ci.yml/badge.svg)](https://github.com/tester128mail69-cyber/updatedrecontool2/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/tester123mail69-cyber/updatedrecontool?style=social)](https://github.com/tester123mail69-cyber/updatedrecontool/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/tester123mail69-cyber/updatedrecontool)](https://github.com/tester123mail69-cyber/updatedrecontool/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> **The Ultimate Automated Reconnaissance & Vulnerability Scanner for Bug Bounty Hunters**

---

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Scan Modes](#scan-modes)
- [CLI Examples](#cli-examples)
- [CLI Reference](#cli-reference)
- [API Usage](#api-usage)
- [API Keys Setup](#api-keys-setup)
- [Configuration](#configuration)
- [Plugin Development](#plugin-development)
- [Dashboard Guide](#dashboard-guide)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Description

**GodRecon** is an all-in-one, async-first reconnaissance and vulnerability scanning framework built for bug bounty hunters, penetration testers, and security researchers. It combines 30+ modules — from passive subdomain enumeration to active vulnerability chaining — into a single cohesive tool backed by a beautiful Rich CLI and a full-featured REST API with web dashboard.

Key highlights:
- **Zero configuration required** — works out of the box with no API keys
- **Async-first architecture** — scans thousands of hosts in parallel
- **Plugin system** — drop in custom modules with zero boilerplate
- **AI-powered validation** — reduce false positives with OpenAI, Claude, or Gemini
- **Full reporting pipeline** — JSON, HTML, CSV, Markdown, PDF, HackerOne, Bugcrowd

---

## Features

### Scanner Modules

| Module | Description |
|--------|-------------|
| **Subdomain Enumeration** | 38+ sources — Subfinder, Amass, Assetfinder, Findomain, Chaos, crt.sh, SecurityTrails, Shodan, Censys, VirusTotal, BufferOver, AlienVault, Wayback, CommonCrawl, RapidDNS, Riddler, ThreatCrowd, HackerTarget, DNSDumpster, GitHub Code Search, and more |
| **Subdomain Supercharger** | DNS brute-force, permutation engine, recursive enumeration, AXFR zone transfer, TLS cert scraping, reverse DNS, NOERROR enumeration, favicon hash matching, SPF/TXT mining |
| **Port Scanning** | Full 65535-port or top-ports scan with banner grabbing and service detection |
| **Directory Bruteforce** | Wordlist-based content/directory discovery with recursive scanning, backup file detection, and sensitive file checks |
| **Vulnerability Scanning** | SQLi, RCE, SSRF, XSS, LFI/RFI, XXE, SSTI, IDOR, CSRF, CORS, Open Redirect, Command Injection, Deserialization, JWT attacks, GraphQL injection (P1–P5) |
| **WHOIS Lookup** | Domain registration data, registrar info, expiry dates, and ownership history |
| **DNS Analysis** | Full DNS intelligence — A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA records; DNSSEC check; zone transfer attempt; passive DNS |
| **HTTP Headers Analysis** | Security header audit (HSTS, CSP, X-Frame-Options, etc.), CORS misconfiguration, cookie flags |
| **SSL/TLS Analysis** | Certificate transparency, cipher suite audit, protocol version checks, certificate expiry, full grading |
| **Technology Detection** | Detect frameworks, web servers, CMSs, CDNs, WAFs, and libraries via headers, HTML, and favicon hash |
| **Wayback Machine Mining** | Historical URL and parameter extraction from the Wayback Machine and CommonCrawl |
| **JS Analysis & Secrets** | 16 regex patterns + entropy analysis to find API keys, tokens, and credentials in JavaScript files |
| **Email Harvesting** | Collect email addresses via OSINT sources, Google dorking, and metadata extraction |
| **Social Recon** | Identify social media profiles, GitHub accounts, and public data tied to the target |
| **API Fuzzing** | Discover and fuzz API endpoints; detect GraphQL introspection, broken object-level auth, and mass assignment |
| **Cloud Enumeration** | S3, Azure Blob, GCP, Firebase, Kubernetes, and Docker misconfiguration scanning; bucket bruteforce |
| **Screenshots** | Headless browser screenshots of discovered web assets for visual recon |
| **Full Recon** | One-command `--full` flag that activates every module for exhaustive attack surface mapping |
| **WAF Detection & Bypass** | Cloudflare, Akamai, AWS WAF, Sucuri, Imperva, ModSecurity, F5 detection and bypass techniques |
| **Nuclei Integration** | 8000+ community Nuclei templates |
| **Out-of-Band (OOB) Detection** | Blind SSRF, XSS, SQLi, XXE, RCE via Interactsh |
| **Authenticated Scanning** | Cookie, bearer token, and custom header injection |
| **Parameter Discovery** | Automatic parameter enumeration, JS mining, and form extraction |
| **Auto Vulnerability Chaining** | Detects and chains multi-step exploits |
| **Passive Recon** | Shodan, Censys, SecurityTrails, VirusTotal intelligence gathering |
| **Mobile API Extraction** | APK decompilation and endpoint extraction |
| **Supply Chain Analysis** | SRI checks and vulnerable dependency detection |
| **GitHub/GitLab Dorking** | Automated code search for secrets and sensitive data |
| **Broken Authentication Scanner** | Session, token, and auth flow testing |
| **Cache Poisoning Scanner** | Web cache poisoning detection |
| **Scan Diffing** | Compare two scans to detect new findings |
| **Continuous Monitoring** | Scheduled rescans with Slack, Discord, Telegram, and Webhook alerts |
| **AI-Powered Validation** | Reduce false positives via OpenAI, Claude, Gemini, Ollama, or pattern-based validation |
| **Bug Report Generation** | Auto-generate HackerOne, Bugcrowd, Markdown, and PDF reports |

### Dashboard Features (70)

<details>
<summary>Click to expand all 70 dashboard features</summary>

**Core Features**
- Live scan progress with real-time updates
- Multi-target management
- Scan history and result storage
- REST API with OpenAPI docs

**Visual & UX**
- Dark/light theme toggle
- Responsive sidebar navigation
- Global search (Ctrl+K)
- Toast notifications
- Rich data tables with sorting/filtering

**Productivity**
- Kanban-style findings board
- Bulk actions on findings
- CSV/JSON/HTML/PDF export
- Report generation wizard
- Scheduled scan management

**Analytics**
- Findings severity breakdown
- Subdomain growth over time
- Vulnerability trend charts
- Module performance metrics
- Leaderboard view

**Security**
- API key authentication
- CORS configuration
- Rate limiting
- Audit log / activity feed

**WOW Factor**
- Attack surface visualization
- Interactive findings timeline
- AI validation panel
- Bug bounty matcher
- Secrets explorer

**Scanner Panels**
- Subdomain enumeration panel
- Vulnerability findings panel
- Port scan results
- Technology fingerprint view
- Cloud misconfiguration panel

**Power Features**
- Scan diffing view
- Continuous monitoring dashboard
- Alert management
- Webhook configuration
- Multi-region scan control

</details>

---

## Installation

### Requirements

- Python 3.10+
- Git (for source install)
- Docker (optional)

### Option 1 — pip (recommended)

```bash
pip install godrecon
```

For screenshot support:

```bash
pip install "godrecon[screenshots]"
playwright install chromium
```

### Option 2 — From Source

```bash
# Clone the repository
git clone https://github.com/tester128mail69-cyber/updatedrecontool2.git
cd updatedrecontool2

# Install in editable mode
pip install -e .

# Or install all dependencies directly
pip install -r requirements.txt
```

For development dependencies (testing, linting):

```bash
pip install -e ".[dev]"
```

### Option 3 — Docker

```bash
# Pull and run
docker pull ghcr.io/tester128mail69-cyber/godrecon:latest
docker run --rm ghcr.io/tester128mail69-cyber/godrecon:latest scan --target example.com

# Or build locally
git clone https://github.com/tester128mail69-cyber/updatedrecontool2.git
cd updatedrecontool2
docker build -t godrecon .
docker run --rm godrecon scan --target example.com
```

Using Docker Compose (includes API server + dashboard):

```bash
docker-compose up
# Dashboard available at http://localhost:8000/dashboard/
```

---

## Quick Start

```bash
# Run a standard scan
godrecon scan --target example.com

# Run a full scan and save HTML report
godrecon scan --target example.com --full --format html -o report.html

# Quick scan (subdomain enum + top vulnerabilities)
godrecon scan --target example.com --mode quick

# Deep scan — every module, no timeouts
godrecon scan --target example.com --deep --oob --fuzzing

# Subdomain enumeration only
godrecon scan --target example.com --subs-only

# Launch the API server and dashboard
godrecon api
# Open: http://127.0.0.1:8000/dashboard/
```

---

## Scan Modes

| Mode | Duration | What it does | Command |
|------|----------|-------------|---------|
| **Quick** | 30–45 min | Subdomains + top vulns + secrets | `godrecon scan --target example.com --mode quick` |
| **Standard** | 1.5–2.5 hrs | All modules except fuzzing/OOB | `godrecon scan --target example.com` |
| **Deep / GOD MODE** | 4–6 hrs | Every module, no timeouts | `godrecon scan --target example.com --deep` |
| **Continuous** | 24/7 | Recurring scans with change alerts | `godrecon monitor example.com --interval daily` |

---

## CLI Examples

```bash
# Subdomain enumeration only
godrecon scan --target example.com --subs-only

# Port scan + service detection
godrecon scan --target example.com --ports

# Directory bruteforce (content discovery)
godrecon scan --target example.com --full   # content_discovery module is included

# Vulnerability scan with Nuclei templates
godrecon scan --target example.com --nuclei

# WHOIS + DNS + headers + SSL recon
godrecon scan --target example.com --mode quick  # all passive modules included

# SSL/TLS analysis
godrecon scan --target example.com --full

# Technology detection
godrecon scan --target example.com --full

# Wayback Machine URL mining
godrecon scan --target example.com --wayback

# JavaScript secrets analysis
godrecon scan --target example.com --js-secrets

# Email harvesting + social recon (OSINT module)
godrecon scan --target example.com --passive-recon

# API fuzzing
godrecon scan --target example.com --fuzzing

# Cloud bucket enumeration
godrecon scan --target example.com --full

# Screenshots of discovered assets
godrecon scan --target example.com --screenshots

# Full recon — every module enabled
godrecon scan --target example.com --full

# Authenticated scan
godrecon scan --target example.com --auth-token "Bearer eyJ..."

# AI-powered validation to reduce false positives
godrecon scan --target example.com --full --ai-provider openai

# Save output in multiple formats
godrecon scan --target example.com --format html -o report.html
godrecon scan --target example.com --format json -o results.json
godrecon scan --target example.com --format pdf -o report.pdf

# Generate bug bounty report
godrecon report results.json --format hackerone -o h1_report

# Diff two scans to detect new attack surface
godrecon diff scan_jan.json scan_feb.json

# Continuous monitoring with Slack notifications
godrecon monitor example.com --interval daily --notify slack

# Start monitoring schedules
godrecon schedules list
godrecon schedules add --target example.com --interval daily
```

---

## CLI Reference

### `godrecon scan`

| Flag | Description | Example |
|------|-------------|---------|
| `--target` | Target domain, IP, or CIDR **(required)** | `--target example.com` |
| `--full` | Run all modules | `--full` |
| `--deep` | Deep scan mode — exhaustive, no timeouts | `--deep` |
| `--mode` | Scan mode: `quick`, `standard`, `deep`, `continuous` | `--mode quick` |
| `--subs-only` | Subdomain enumeration only | `--subs-only` |
| `--ports` | Enable port scanning | `--ports` |
| `--screenshots` | Enable screenshots | `--screenshots` |
| `--nuclei/--no-nuclei` | Run Nuclei templates (default: on) | `--no-nuclei` |
| `--oob` | Enable OOB detection | `--oob` |
| `--fuzzing` | Enable fuzzing engine | `--fuzzing` |
| `--waf-bypass` | Enable WAF bypass techniques | `--waf-bypass` |
| `--auth-cookie` | Session cookie for authenticated scanning | `--auth-cookie session=abc123` |
| `--auth-token` | Bearer token for authenticated scanning | `--auth-token eyJ...` |
| `--auth-header` | Custom auth header | `--auth-header X-API-Key=secret` |
| `--ai-provider` | AI validation provider: `pattern`, `openai`, `anthropic`, `gemini`, `ollama` | `--ai-provider openai` |
| `--passive-recon/--no-passive-recon` | Enable passive recon (default: on) | `--passive-recon` |
| `--wayback/--no-wayback` | Enable Wayback Machine mining (default: on) | `--wayback` |
| `--cache-poisoning/--no-cache-poisoning` | Enable cache poisoning scanner (default: on) | `--cache-poisoning` |
| `--js-secrets/--no-js-secrets` | Enable JS secrets scanning (default: on) | `--js-secrets` |
| `--git-dork` | Enable GitHub/GitLab dorking | `--git-dork` |
| `--output` / `-o` | Output file path | `-o report.html` |
| `--format` / `-f` | Output format: `json`, `csv`, `html`, `pdf`, `md` | `-f html` |
| `--threads` | Concurrency level (default: 50) | `--threads 100` |
| `--min-confidence` | Minimum confidence threshold 0.0–1.0 (default: 0.5) | `--min-confidence 0.7` |
| `--verify/--no-verify` | Cross-validation pass | `--verify` |
| `--resume` | Resume interrupted scan | `--resume` |

### Other Commands

```bash
# Start the API server + dashboard
godrecon api --host 0.0.0.0 --port 8000
godrecon api --api-key your-strong-api-key-here

# Generate bug bounty report from scan JSON
godrecon report scan.json --format hackerone -o report

# Compare two scans
godrecon diff scan1.json scan2.json

# Manage monitoring schedules
godrecon schedules list
godrecon schedules add --target example.com --interval daily
godrecon schedules remove --id <schedule_id>

# Show version
godrecon version
```

---

## API Usage

GodRecon ships a full REST API built on FastAPI. Start the server with:

```bash
godrecon api
# or: python main.py api
```

The interactive OpenAPI docs are available at `http://127.0.0.1:8000/docs`.

### Authentication

Protect the server by setting an API key:

```bash
godrecon api --api-key your-strong-api-key-here
```

Pass the key in all requests via the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-strong-api-key-here" http://127.0.0.1:8000/health
```

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check and version info |
| `GET` | `/modules` | List all available scan modules |
| `POST` | `/scan` | Start a new scan |
| `GET` | `/scan/{scan_id}` | Get scan status and progress |
| `GET` | `/scan/{scan_id}/result` | Retrieve full scan results |
| `DELETE` | `/scan/{scan_id}` | Cancel a running scan |
| `GET` | `/scans` | List all scans |
| `WebSocket` | `/ws/{scan_id}` | Real-time scan event stream |

### Example: Start a Scan

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "modules": ["subdomains", "ports", "vulns", "ssl"],
    "options": {
      "threads": 50,
      "timeout": 10
    }
  }'
```

Response:

```json
{
  "scan_id": "a1b2c3d4-5678-9abc-def0-1234567890ab",
  "status": "queued",
  "target": "example.com"
}
```

### Example: Poll for Results

```bash
curl http://127.0.0.1:8000/scan/a1b2c3d4-5678-9abc-def0-1234567890ab/result
```

### Example: Real-time WebSocket Stream

```python
import asyncio
import websockets
import json

async def stream_scan():
    uri = "ws://127.0.0.1:8000/ws/a1b2c3d4-5678-9abc-def0-1234567890ab"
    async with websockets.connect(uri) as ws:
        async for message in ws:
            event = json.loads(message)
            print(event)

asyncio.run(stream_scan())
```

---

## API Keys Setup

All API keys are **optional** — GODRECON works without them. Keys unlock additional data sources.

| Key | Where to Get | Free Tier | What it Enables |
|-----|-------------|-----------|-----------------|
| **Shodan** | [shodan.io/register](https://account.shodan.io/register) | 100 queries/month | Port data, banners, CVEs |
| **Censys** | [censys.io/register](https://censys.io/register) | 250 queries/month | Host data, certificates |
| **SecurityTrails** | [securitytrails.com](https://securitytrails.com/app/account) | 50 queries/month | Historical DNS, subdomains |
| **VirusTotal** | [virustotal.com](https://www.virustotal.com/gui/join-us) | 500 req/day | Subdomain data, malware info |
| **OpenAI** | [platform.openai.com](https://platform.openai.com/signup) | $5 free credit | AI vulnerability validation |
| **Anthropic (Claude)** | [console.anthropic.com](https://console.anthropic.com) | $5 free credit | AI vulnerability validation |
| **Google (Gemini)** | [aistudio.google.com](https://aistudio.google.com) | Free tier available | AI vulnerability validation |
| **Chaos (ProjectDiscovery)** | [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io) | Free for researchers | Bug bounty subdomain data |
| **GitHub Token** | [github.com/settings/tokens](https://github.com/settings/tokens) | Free | GitHub dorking, code search |

Add keys to `config.yaml`:

```yaml
api_keys:
  shodan: "your-shodan-key"
  censys_id: "your-censys-app-id"
  censys_secret: "your-censys-secret"
  securitytrails: "your-st-key"
  virustotal: "your-vt-key"
  openai: "sk-..."
  anthropic: "sk-ant-..."
  github_token: "ghp_..."
```

---

## Configuration

GodRecon is configured via `config.yaml` (auto-created on first run). You can also pass a custom path with `--config`.

### Key Sections

```yaml
general:
  threads: 50          # Concurrency level
  timeout: 10          # Request timeout (seconds)
  retries: 3           # Retry failed requests
  proxy: null          # HTTP/SOCKS5 proxy URL
  output_dir: "./output"
  output_format: "json"

modules:
  subdomains: true      # Subdomain enumeration
  dns: true             # DNS analysis
  http_probe: true      # HTTP header & security check
  ports: true           # Port scanning
  tech: true            # Technology detection
  osint: true           # WHOIS, email harvesting, social recon
  vulns: true           # Vulnerability scanning
  ssl: true             # SSL/TLS analysis
  content_discovery: true  # Directory bruteforce
  js_secrets: true      # JavaScript secrets analysis
  wayback_mining: true  # Wayback Machine mining
  screenshots: true     # Visual screenshots
  cloud: true           # Cloud enumeration
  fuzzing: false        # API fuzzing (disabled by default)
  nuclei: true          # Nuclei templates
  passive_recon: true   # Shodan/Censys passive recon

port_scan:
  scan_type: "top100"   # top100, top1000, custom, full
  concurrency: 500
  banner_grab: true

content_discovery:
  wordlist: "wordlists/directories.txt"
  concurrency: 50
  recursive: false
  recursive_depth: 2
  check_sensitive_files: true
  check_backups: true

osint:
  whois: true
  social_media: true    # Social recon
  google_dorks: true
  metadata_extraction: true  # Email harvesting

ssl_analysis:
  check_ciphers: true
  check_vulnerabilities: true
  check_certificate: true
  grade: true

api_keys:
  shodan: ""
  censys_id: ""
  censys_secret: ""
  virustotal: ""
  securitytrails: ""
  github: ""

notifications:
  slack:
    enabled: false
    webhook_url: ""
  discord:
    enabled: false
    webhook_url: ""
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""

plugins:
  enabled: true
  plugin_dir: "~/.godrecon/plugins"
```

Copy `.env.example` to `.env` to set environment variable overrides:

```bash
cp .env.example .env
```

---

## Plugin Development

GodRecon has a first-class plugin system. Drop a `.py` file in `~/.godrecon/plugins/` (configurable via `plugins.plugin_dir`) and it will be auto-loaded on startup.

### Minimal Plugin Example

```python
# ~/.godrecon/plugins/my_scanner.py

from godrecon.modules.base import BaseModule, ModuleResult, Finding
from godrecon.core.config import Config


class MyScanner(BaseModule):
    name = "my_scanner"
    description = "My custom scanner module"
    version = "1.0.0"
    category = "recon"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        findings = []

        # Your async scanning logic here
        result = await self._check_something(target)
        if result:
            findings.append(Finding(
                title="My Finding",
                description=f"Found something on {target}",
                severity="medium",
                data={"detail": result},
                tags=["custom", "my_scanner"],
                confidence=0.9,
                source_module=self.name,
            ))

        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=findings,
        )

    async def _check_something(self, target: str) -> str:
        # Example: async HTTP request, DNS lookup, etc.
        return ""
```

### Plugin API Reference

| Attribute / Method | Description |
|--------------------|-------------|
| `name: str` | Unique module identifier (required) |
| `description: str` | Human-readable description |
| `version: str` | Module version string |
| `category: str` | Category tag (`recon`, `vuln`, `osint`, etc.) |
| `async _execute(target, config) -> ModuleResult` | Main scan logic (required) |
| `self.logger` | Pre-configured logger (`logging.Logger`) |

The `Finding` dataclass accepts:

| Field | Type | Description |
|-------|------|-------------|
| `title` | `str` | Short finding title |
| `description` | `str` | Detailed description |
| `severity` | `str` | `info`, `low`, `medium`, `high`, `critical` |
| `data` | `dict` | Arbitrary extra data |
| `tags` | `list[str]` | Classification tags |
| `confidence` | `float` | 0.0–1.0 confidence score |
| `evidence` | `str` | Raw evidence string |
| `impact` | `str` | Business impact description |
| `cvss_score` | `float \| None` | CVSS score if applicable |

### Registering a Plugin

Plugins are auto-discovered — no registration required. Just place the file in the plugin directory and run:

```bash
godrecon scan --target example.com
# Plugin 'my_scanner' will appear in the output automatically
```

To verify your plugin loaded:

```bash
godrecon api
curl http://127.0.0.1:8000/modules | python -m json.tool | grep my_scanner
```

---

## Dashboard Guide

```bash
# Start the server
python main.py api

# Open in browser
# Dashboard: http://127.0.0.1:8000/dashboard/
# API Docs:  http://127.0.0.1:8000/docs
```

The dashboard provides a full web UI with 70 features across:

- **Scans** — Start scans, view progress, browse history
- **Findings** — All vulnerabilities sorted by severity
- **Subdomains** — Complete subdomain enumeration results
- **Vulnerabilities** — P1–P5 vulnerability details
- **Secrets** — JS secrets and leaked credentials
- **Analytics** — Charts, trends, and statistics
- **Reports** — Generate and download reports
- **Targets** — Manage your target list
- **Alerts** — Monitoring alerts and notifications
- **Settings** — API keys, notifications, preferences

See [docs/DASHBOARD_GUIDE.md](docs/DASHBOARD_GUIDE.md) for the full guide.

---

## Architecture

```
godrecon/
├── ai/                  # AI validation (OpenAI, Claude, Gemini, Ollama, Pattern)
├── api/                 # FastAPI server
├── core/                # Engine, config, scheduler, verifier, PoC generator
├── dashboard/           # 70-feature web dashboard
│   ├── templates/       # Jinja2 HTML templates (33+ pages)
│   ├── static/          # CSS, JS, assets
│   └── routes.py        # 75 routes + 30 API endpoints
├── modules/             # All scanner modules
│   ├── subdomains/      # 38+ subdomain sources
│   ├── vulns/           # P1-P5 vulnerability detectors
│   ├── passive_recon/   # Shodan, Censys, SecurityTrails, VirusTotal
│   ├── cloud_misconfig/ # S3, Azure, GCP, Firebase, K8s
│   └── ...              # 20+ more module directories
├── monitoring/          # Slack, Discord, Telegram notifications
├── reporting/           # JSON, HTML, CSV, Markdown, PDF, Bug Reports
├── utils/               # HTTP client, DNS resolver, auth client, helpers
└── cli.py               # Typer + Rich CLI
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full technical overview.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-module`)
3. Add your module under `godrecon/modules/`
4. Inherit from `BaseModule` and implement `_execute`
5. Submit a Pull Request

---

## License

MIT License — Copyright © 2026 nothingmch69

See [LICENSE](LICENSE) for full text.

---

## Disclaimer

> **For authorized security testing only.**
>
> GodRecon is designed for **legal, authorized penetration testing and bug bounty hunting** on systems you own or have explicit written permission to test. Unauthorized scanning of systems, networks, or applications you do not own or have permission to test is **illegal** in most jurisdictions and may result in civil or criminal liability.
>
> - Always obtain written authorization before testing any system.
> - Comply with all applicable local, state, national, and international laws.
> - Respect the scope and rules of engagement of any bug bounty program.
> - The authors and contributors of GodRecon accept **no responsibility** for misuse of this tool.
>
> **Use responsibly. Hack ethically.**

---

<p align="center">Made with ❤️ by <a href="https://github.com/nothingmch69">nothingmch69</a></p>

