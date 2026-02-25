# Usage Guide

## Basic Scanning

```bash
# Simplest scan — subdomains + basic recon
python main.py scan --target example.com

# Full scan — all modules
python main.py scan --target example.com --full

# Save results to file
python main.py scan --target example.com --format json -o results.json
python main.py scan --target example.com --format html -o report.html
```

---

## Scan Modes

### Quick Scan (30–45 minutes)
Fast recon: subdomains, top vulnerabilities, secrets scanning.

```bash
python main.py scan --target example.com --mode quick
```

### Standard Scan (1.5–2.5 hours)
Balanced coverage. Runs all modules except fuzzing and OOB.

```bash
python main.py scan --target example.com
# or explicitly:
python main.py scan --target example.com --mode standard
```

### Deep Scan / GOD MODE (4–6 hours)
Everything enabled, no timeouts, maximum coverage.

```bash
python main.py scan --target example.com --deep --oob --fuzzing --nuclei
```

### Continuous Mode (24/7)
Rescans on a schedule and alerts you to new findings.

```bash
python main.py monitor example.com --interval daily --notify slack
```

---

## Authenticated Scanning

Scan behind a login wall by providing authentication credentials.

```bash
# Cookie-based auth
python main.py scan --target example.com --auth-cookie "session=abc123def456"

# Bearer token
python main.py scan --target example.com --auth-token "eyJhbGciOiJIUzI1NiJ9..."

# Custom auth header
python main.py scan --target example.com --auth-header "X-API-Key=mysecret"
```

---

## Using the Dashboard

```bash
# Start the API server
python main.py api

# Open in browser
# Dashboard: http://127.0.0.1:8000/dashboard/
# API Docs:  http://127.0.0.1:8000/docs
```

Start scans from the dashboard UI, monitor progress in real-time, and browse all findings organized by severity.

---

## Generating Reports

```bash
# Generate HTML report during scan
python main.py scan --target example.com --format html -o report.html

# Generate bug bounty report from saved scan JSON
python main.py report scan.json --format hackerone -o h1_report
python main.py report scan.json --format bugcrowd -o bc_report
python main.py report scan.json --format markdown -o report
```

---

## Setting Up Continuous Monitoring

```bash
# Monitor with daily scans, Slack alerts
python main.py monitor example.com --interval daily --notify slack

# Multiple notification channels
python main.py monitor example.com --interval hourly --notify slack --notify discord

# List active schedules
python main.py schedules list

# Remove a schedule
python main.py schedules remove --id <schedule_id>
```

Configure notification webhooks in `config.yaml`:
```yaml
notifications:
  slack_webhook: "https://hooks.slack.com/services/..."
  discord_webhook: "https://discord.com/api/webhooks/..."
  telegram_bot_token: "..."
  telegram_chat_id: "..."
```

---

## Using AI Validation

Reduce false positives with AI-powered vulnerability validation.

```bash
# Pattern-based (no API key needed, default)
python main.py scan --target example.com --ai-provider pattern

# OpenAI GPT-4
python main.py scan --target example.com --ai-provider openai

# Anthropic Claude
python main.py scan --target example.com --ai-provider anthropic

# Google Gemini
python main.py scan --target example.com --ai-provider gemini

# Local Ollama (no API key needed)
python main.py scan --target example.com --ai-provider ollama
```

Add API keys to `config.yaml`:
```yaml
ai:
  openai_api_key: "sk-..."
  anthropic_api_key: "sk-ant-..."
  google_api_key: "..."
```

---

## Scan Diffing

Compare two scans to find new and resolved findings.

```bash
# Run two scans
python main.py scan --target example.com --format json -o scan1.json
# (some time later)
python main.py scan --target example.com --format json -o scan2.json

# Compare them
python main.py diff scan1.json scan2.json
```

---

## Configuration

Edit `config.yaml` to set defaults:

```yaml
general:
  threads: 50
  timeout: 10
  output_dir: ./output

api_keys:
  shodan: "your-key"
  virustotal: "your-key"
```

Environment variable overrides:
```bash
export GODRECON__GENERAL__THREADS=100
export GODRECON__API_KEYS__SHODAN=your-key
```
