# Architecture

Technical overview of how GODRECON works internally.

---

## Project Structure

```
godrecon/
├── __init__.py              # Version, author metadata
├── cli.py                   # Typer + Rich CLI (all commands)
│
├── core/
│   ├── engine.py            # Async scan orchestrator
│   ├── config.py            # Pydantic v2 config models + YAML loader
│   ├── scope.py             # Target & scope management
│   ├── scheduler.py         # Async task queue with priority/retry
│   ├── verifier.py          # Cross-validation / finding verification
│   └── poc_generator.py     # Proof-of-concept snippet generator
│
├── modules/
│   ├── base.py              # BaseModule abstract class
│   ├── subdomains/          # 38+ subdomain discovery sources
│   │   ├── passive.py       # crt.sh, SecurityTrails, VirusTotal, etc.
│   │   ├── brute.py         # DNS brute-force
│   │   ├── permutation.py   # Permutation/alteration engine
│   │   ├── axfr.py          # Zone transfer
│   │   ├── tls_scrape.py    # TLS certificate scraping
│   │   └── supercharger.py  # All supercharger techniques combined
│   ├── vulns/               # P1–P5 vulnerability detectors
│   │   ├── sqli.py          # SQL injection
│   │   ├── rce.py           # Remote code execution
│   │   ├── ssrf.py          # Server-side request forgery
│   │   ├── xss.py           # Cross-site scripting
│   │   ├── lfi.py           # Local/remote file inclusion
│   │   ├── xxe.py           # XML external entity
│   │   ├── ssti.py          # Server-side template injection
│   │   ├── idor.py          # Insecure direct object reference
│   │   ├── cors.py          # CORS misconfiguration
│   │   ├── jwt.py           # JWT attacks
│   │   └── graphql.py       # GraphQL injection
│   ├── passive_recon/       # Shodan, Censys, SecurityTrails, VirusTotal
│   ├── cloud_misconfig/     # S3, Azure, GCP, Firebase, K8s, Docker
│   ├── dns/                 # DNS intelligence + email security
│   ├── http/                # HTTP probing + security headers
│   ├── ssl/                 # SSL/TLS analysis
│   ├── tech/                # Technology fingerprinting
│   ├── ports/               # Port scanning + banner grabbing
│   ├── takeover/            # Subdomain takeover detection
│   ├── crawl/               # Web spider + JS analyzer
│   ├── content_discovery/   # Directory/file brute-forcing
│   ├── osint/               # WHOIS, dorks, metadata
│   ├── nuclei/              # Nuclei integration
│   ├── oob/                 # Out-of-band detection
│   ├── js_secrets/          # JS secrets + entropy analysis
│   ├── git_dorking/         # GitHub/GitLab code search
│   ├── wayback/             # Wayback Machine mining
│   ├── cache_poisoning/     # Cache poisoning scanner
│   ├── mobile_api/          # APK decompilation + endpoint extraction
│   ├── supply_chain/        # Dependency analysis
│   └── network/             # Traceroute, CDN, ASN, geolocation
│
├── ai/                      # AI validation providers
│   ├── base.py              # BaseValidator abstract class
│   ├── pattern.py           # Pattern-based (no API key)
│   ├── openai_validator.py  # OpenAI GPT-4
│   ├── anthropic_validator.py  # Claude
│   ├── gemini_validator.py  # Google Gemini
│   └── ollama_validator.py  # Local Ollama
│
├── api/                     # FastAPI REST server
│   ├── server.py            # App setup, CORS, middleware
│   └── routes/              # API route handlers
│
├── dashboard/               # Web dashboard
│   ├── routes.py            # 75 routes + 30 API endpoints
│   ├── templates/           # 33+ Jinja2 HTML templates
│   └── static/              # CSS, JS, assets
│
├── monitoring/              # Continuous monitoring
│   ├── monitor.py           # ContinuousMonitor
│   ├── scheduler.py         # ScanScheduler (cron-like)
│   ├── diff.py              # ScanDiffer
│   └── notifiers/           # Slack, Discord, Telegram, Webhook
│
├── reporting/               # Report generators
│   ├── json_report.py       # JSON export
│   ├── html.py              # HTML report
│   ├── csv_report.py        # CSV export
│   ├── markdown_report.py   # Markdown report
│   ├── pdf.py               # PDF export
│   └── bug_report.py        # HackerOne / Bugcrowd formats
│
├── data/                    # Static data files
│   ├── ports.json           # Port/service database
│   ├── tech_signatures.json # Technology fingerprints
│   └── takeover_fps.json    # Subdomain takeover fingerprints
│
└── utils/
    ├── http_client.py       # Async HTTP with pooling, retry, UA rotation
    ├── dns_resolver.py      # Async DNS with caching, all record types
    ├── auth_client.py       # Authenticated HTTP client
    ├── logger.py            # Rich-based structured logging
    └── helpers.py           # Utility functions
```

---

## How the Scan Engine Works

1. **Initialization** — `ScanEngine` loads config, initializes modules based on enabled flags
2. **Scope check** — All targets are validated against scope rules
3. **Parallel execution** — Modules run concurrently via `asyncio` task groups
4. **Circuit breaker** — Each module has a circuit breaker; failures don't cascade
5. **Event streaming** — Modules emit events (`module_started`, `finding`, `module_finished`)
6. **Cross-validation** — In `--verify` or `--full` mode, findings are re-validated by a second pass
7. **AI scoring** — Each finding gets a confidence score (0.0–1.0) from the AI validator
8. **Result aggregation** — All module results are merged into a `ScanResult` object
9. **Reporting** — `ScanResult` is serialized to the requested output format

---

## Data Flow

```
Target Input
     │
     ▼
ScanEngine.run()
     │
     ├── SubdomainModule  ──► findings ──►┐
     ├── VulnModule       ──► findings ──►│
     ├── PortModule       ──► findings ──►├── ScanResult
     ├── SSLModule        ──► findings ──►│
     ├── CloudModule      ──► findings ──►│
     └── ...              ──► findings ──►┘
                                          │
                                          ▼
                                   AI Validator
                                   (confidence scoring)
                                          │
                                          ▼
                                   Cross-Validator
                                   (--verify mode)
                                          │
                                          ▼
                                   Report Generator
                                   (JSON/HTML/PDF/etc.)
```

---

## Module System

Every scanner module inherits from `BaseModule`:

```python
class BaseModule(ABC):
    name: str          # Unique module identifier
    description: str   # Human-readable description

    @abstractmethod
    async def _execute(self, target: str, **kwargs) -> ModuleResult:
        """Implement scanner logic here."""
        ...
```

`ModuleResult` contains:
- `findings: list[Finding]` — List of findings
- `error: str | None` — Error message if the module failed
- `metadata: dict` — Module-specific metadata

`Finding` contains:
- `title: str` — Finding title
- `severity: str` — `critical`, `high`, `medium`, `low`, `info`
- `confidence: float` — 0.0–1.0
- `evidence: str` — Evidence supporting the finding
- `remediation: str` — How to fix it
- `cvss_score: float | None` — CVSS score if applicable

---

## Configuration System

Config is loaded from (in priority order):
1. Environment variables (`GODRECON__SECTION__KEY`)
2. Config file (`config.yaml` or `--config` path)
3. Built-in defaults

The config is a Pydantic v2 model (`GodReconConfig`) with nested sections for `general`, `modules`, `api_keys`, `ai`, `waf`, `auth`, `deep_scan`, etc.
