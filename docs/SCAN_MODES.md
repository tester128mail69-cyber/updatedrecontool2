# Scan Modes

GODRECON offers four scan modes to balance speed and coverage.

---

## Quick Scan

**Duration:** 30–45 minutes  
**Use case:** Fast initial recon, time-sensitive engagements

What it does:
- Subdomain enumeration (fast passive sources only)
- Top vulnerability checks (P1/P2 only)
- JS secrets scanning
- Basic HTTP probing

Disabled in quick mode:
- Fuzzing
- Full Nuclei scan
- OOB detection
- Multi-region scanning
- Collaboration features

```bash
python main.py scan --target example.com --mode quick
```

---

## Standard Scan (Default)

**Duration:** 1.5–2.5 hours  
**Use case:** Most bug bounty engagements, thorough but reasonable

What it does:
- Full subdomain enumeration (all 38+ sources)
- All vulnerability detectors (P1–P5)
- JS secrets + GitHub dorking
- Passive recon (Shodan, Censys, SecurityTrails, VirusTotal if keys available)
- Wayback Machine mining
- Cache poisoning scanner
- Parameter discovery
- Supply chain analysis
- SSL/TLS + email security analysis
- Port scanning (top ports)
- Technology fingerprinting
- AI validation (pattern-based by default)

```bash
# Standard scan (default)
python main.py scan --target example.com

# With HTML report
python main.py scan --target example.com --format html -o report.html

# With AI validation
python main.py scan --target example.com --ai-provider openai
```

---

## Deep Scan / GOD MODE

**Duration:** 4–6 hours  
**Use case:** Maximum coverage, critical targets, comprehensive pentests

What it does (everything):
- Everything in Standard Scan, plus:
- Fuzzing engine (full parameter fuzzing)
- OOB detection (blind SSRF, XSS, SQLi, XXE, RCE callback)
- Full Nuclei scan (8000+ templates)
- WAF bypass techniques
- Recursive subdomain enumeration (depth 5)
- Full port scan (all 65535 ports)
- Deep web crawling (10 levels, 5000 pages)
- No module timeouts
- Cross-validation pass on all findings

```bash
# Full deep scan
python main.py scan --target example.com --deep

# Deep scan with all options explicitly
python main.py scan --target example.com --deep --oob --fuzzing --nuclei --waf-bypass

# Deep scan with authenticated context
python main.py scan --target example.com --deep --auth-cookie "session=abc123"

# Deep scan with AI validation
python main.py scan --target example.com --deep --ai-provider openai
```

---

## Continuous Mode (24/7 Monitoring)

**Duration:** Runs indefinitely on a schedule  
**Use case:** Bug bounty programs, ongoing security monitoring, detect new attack surface

What it does:
- Rescans on a configurable schedule (hourly / daily / weekly)
- Compares new scan with previous results
- Alerts you to new findings via Slack / Discord / Telegram / Webhook
- Maintains scan history and trend data
- Dashboard shows new vs. resolved findings over time

```bash
# Start continuous monitoring (daily scans, Slack alerts)
python main.py monitor example.com --interval daily --notify slack

# Hourly with Discord
python main.py monitor example.com --interval hourly --notify discord

# Multiple channels
python main.py monitor example.com --interval daily --notify slack --notify telegram

# Custom interval (every 4 hours = 14400 seconds)
python main.py monitor example.com --interval 14400
```

Configure webhooks in `config.yaml`:
```yaml
notifications:
  slack_webhook: "https://hooks.slack.com/services/T.../B.../..."
  discord_webhook: "https://discord.com/api/webhooks/..."
  telegram_bot_token: "123456:ABC-..."
  telegram_chat_id: "-100123456"
```

---

## Mode Comparison

| Feature | Quick | Standard | Deep | Continuous |
|---------|-------|----------|------|------------|
| Subdomain sources | Fast (10+) | All (38+) | All (38+) | All (38+) |
| Recursive enumeration | ❌ | 2 levels | 5 levels | 2 levels |
| Vulnerability detection | P1/P2 only | P1–P5 | P1–P5 | P1–P5 |
| Fuzzing | ❌ | ❌ | ✅ | Optional |
| Nuclei templates | ❌ | ✅ | ✅ (all) | ✅ |
| OOB detection | ❌ | ❌ | ✅ | Optional |
| WAF bypass | ❌ | ❌ | ✅ | Optional |
| Port scanning | Top 100 | Top 1000 | All 65535 | Top 1000 |
| Web crawling | ❌ | 3 levels | 10 levels | 3 levels |
| JS secrets | ✅ | ✅ | ✅ | ✅ |
| Passive recon | Basic | Full | Full | Full |
| AI validation | ✅ | ✅ | ✅ + verify | ✅ |
| Approximate time | 30–45 min | 1.5–2.5 hrs | 4–6 hrs | ∞ |
