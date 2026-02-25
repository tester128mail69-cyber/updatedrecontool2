# CLI Reference

Complete reference for all GODRECON CLI commands and flags.

---

## `godrecon scan`

Run a reconnaissance scan against a target.

```bash
python main.py scan --target <domain> [OPTIONS]
```

### Target Options

| Flag | Type | Description | Example |
|------|------|-------------|---------|
| `--target` / `-t` | TEXT | Target domain, IP, or CIDR **(required)** | `--target example.com` |

### Scan Mode Options

| Flag | Type | Default | Description | Example |
|------|------|---------|-------------|---------|
| `--full` | FLAG | off | Run all modules | `--full` |
| `--deep` | FLAG | off | Deep scan — exhaustive, no timeouts | `--deep` |
| `--mode` / `-m` | TEXT | `standard` | Scan mode: `quick`, `standard`, `deep`, `continuous` | `--mode quick` |
| `--subs-only` | FLAG | off | Subdomain enumeration only | `--subs-only` |

### Module Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ports` | FLAG | off | Enable port scanning |
| `--screenshots` | FLAG | off | Enable screenshots |
| `--nuclei/--no-nuclei` | BOOL | on | Run Nuclei templates |
| `--oob` | FLAG | off | Enable OOB detection |
| `--fuzzing` | FLAG | off | Enable fuzzing engine |
| `--waf-bypass` | FLAG | off | Enable WAF bypass techniques |
| `--js-secrets/--no-js-secrets` | BOOL | on | Enable JS secrets scanning |
| `--git-dork` | FLAG | off | Enable GitHub/GitLab dorking |
| `--passive-recon/--no-passive-recon` | BOOL | on | Enable passive recon (Shodan, Censys, etc.) |
| `--wayback/--no-wayback` | BOOL | on | Enable Wayback Machine mining |
| `--cache-poisoning/--no-cache-poisoning` | BOOL | on | Enable cache poisoning scanner |
| `--param-discovery/--no-param-discovery` | BOOL | on | Enable parameter discovery |
| `--supply-chain/--no-supply-chain` | BOOL | on | Enable supply chain analysis |
| `--apk` | PATH | — | APK file path for mobile API extraction |

### Authentication Options

| Flag | Type | Description | Example |
|------|------|-------------|---------|
| `--auth-cookie` | TEXT | Session cookie (format: `name=value`) | `--auth-cookie session=abc123` |
| `--auth-token` | TEXT | Bearer token | `--auth-token eyJ...` |
| `--auth-header` | TEXT | Custom auth header (format: `Header-Name=value`) | `--auth-header X-API-Key=secret` |

### AI & Validation Options

| Flag | Type | Default | Description | Example |
|------|------|---------|-------------|---------|
| `--ai-provider` | TEXT | `pattern` | AI provider: `pattern`, `openai`, `anthropic`, `gemini`, `ollama` | `--ai-provider openai` |
| `--verify/--no-verify` | BOOL | auto | Cross-validation pass (default: on in `--full` mode) | `--verify` |
| `--min-confidence` | FLOAT | `0.5` | Minimum confidence threshold (0.0–1.0) | `--min-confidence 0.7` |

### Output Options

| Flag | Type | Default | Description | Example |
|------|------|---------|-------------|---------|
| `--output` / `-o` | PATH | — | Output file path | `-o report.html` |
| `--format` / `-f` | TEXT | `json` | Output format: `json`, `csv`, `html`, `pdf`, `md` | `-f html` |
| `--report-format` | TEXT | — | Bug report format: `json`, `html`, `markdown`, `pdf`, `hackerone`, `bugcrowd` | `--report-format hackerone` |

### Performance Options

| Flag | Type | Default | Description | Example |
|------|------|---------|-------------|---------|
| `--threads` | INT | `50` | Concurrency level | `--threads 100` |
| `--resume` | FLAG | off | Resume interrupted scan | `--resume` |

### Misc Options

| Flag | Type | Description |
|------|------|-------------|
| `--silent` | FLAG | Minimal output (for scripting) |
| `--verbose` / `-v` | FLAG | Verbose output |
| `--config` | PATH | Custom config file path |

---

## `godrecon api`

Start the REST API server and web dashboard.

```bash
python main.py api [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | Bind address |
| `--port` / `-p` | `8000` | TCP port |
| `--api-key` | — | API key for authentication |
| `--config` | — | Custom config file |

```bash
# Default (localhost only)
python main.py api

# Public access
python main.py api --host 0.0.0.0 --port 8080

# With API key auth
python main.py api --api-key mysecretkey
```

---

## `godrecon monitor`

Start continuous monitoring for a target.

```bash
python main.py monitor <target> [OPTIONS]
```

| Argument/Flag | Description | Example |
|---------------|-------------|---------|
| `target` | Target domain to monitor **(required)** | `example.com` |
| `--interval` / `-i` | Scan interval: `hourly`, `daily`, `weekly`, or seconds | `--interval daily` |
| `--notify` / `-n` | Notification backends: `slack`, `discord`, `telegram`, `webhook` | `--notify slack` |

---

## `godrecon schedules`

Manage scan schedules.

```bash
python main.py schedules <action> [OPTIONS]
```

| Action | Description |
|--------|-------------|
| `list` | List all schedules |
| `add` | Add a new schedule (requires `--target`) |
| `remove` | Remove a schedule (requires `--id`) |

```bash
python main.py schedules list
python main.py schedules add --target example.com --interval daily
python main.py schedules remove --id abc123
```

---

## `godrecon diff`

Compare two scan results.

```bash
python main.py diff <scan1.json> <scan2.json>
```

---

## `godrecon report`

Generate a bug bounty report from a scan result JSON file.

```bash
python main.py report <scan.json> [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output` / `-o` | `report` | Output file path (without extension) |
| `--format` / `-f` | `markdown` | Format: `markdown`, `hackerone`, `bugcrowd` |

```bash
python main.py report scan.json --format hackerone -o h1_report
python main.py report scan.json --format bugcrowd -o bc_report
python main.py report scan.json -o my_report
```

---

## `godrecon config`

Show the current configuration.

```bash
python main.py config [--config config.yaml]
```

---

## `godrecon version`

Show version information.

```bash
python main.py version
```
