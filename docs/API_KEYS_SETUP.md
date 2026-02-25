# API Keys Setup

All API keys in GODRECON are **optional**. The tool works without any API keys using public data sources. Keys unlock additional data sources and capabilities.

---

## Quick Overview

| Key | Provider | Free Tier | Unlocks |
|-----|----------|-----------|---------|
| Shodan | Shodan | 100 queries/month | Port data, banners, CVEs, device fingerprints |
| Censys | Censys | 250 queries/month | Host data, certificates, open ports |
| SecurityTrails | SecurityTrails | 50 queries/month | Historical DNS, passive subdomains |
| VirusTotal | VirusTotal | 500 req/day | Subdomain data, malware info, URLs |
| OpenAI | OpenAI | $5 free credit | GPT-4 AI vulnerability validation |
| Anthropic | Anthropic | $5 free credit | Claude AI vulnerability validation |
| Google Gemini | Google | Free tier | Gemini AI vulnerability validation |
| Chaos | ProjectDiscovery | Free for researchers | Bug bounty program subdomain datasets |
| GitHub Token | GitHub | Free | GitHub dorking, code search |

---

## Detailed Setup

### Shodan

**Purpose:** Port scanning data, service banners, CVE associations, device fingerprints.

1. Sign up at [https://account.shodan.io/register](https://account.shodan.io/register)
2. Go to [https://account.shodan.io](https://account.shodan.io) and copy your API key
3. Free tier: 100 queries/month, 1 result/query

Add to `config.yaml`:
```yaml
api_keys:
  shodan: "your-shodan-api-key"
```

---

### Censys

**Purpose:** Host enumeration, certificate data, open port discovery.

1. Sign up at [https://censys.io/register](https://censys.io/register)
2. Go to [https://search.censys.io/account/api](https://search.censys.io/account/api)
3. Copy your **App ID** and **Secret**
4. Free tier: 250 queries/month

Add to `config.yaml`:
```yaml
api_keys:
  censys_id: "your-app-id"
  censys_secret: "your-secret"
```

---

### SecurityTrails

**Purpose:** Historical DNS records, passive subdomain discovery, WHOIS history.

1. Sign up at [https://securitytrails.com/app/account](https://securitytrails.com/app/account)
2. Go to API section and copy your key
3. Free tier: 50 queries/month

Add to `config.yaml`:
```yaml
api_keys:
  securitytrails: "your-st-api-key"
```

---

### VirusTotal

**Purpose:** Subdomain enumeration, URL/domain reputation, malware associations.

1. Sign up at [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
2. Go to your profile → API Key
3. Free tier: 500 requests/day, 4 requests/minute

Add to `config.yaml`:
```yaml
api_keys:
  virustotal: "your-vt-api-key"
```

---

### OpenAI (GPT-4)

**Purpose:** AI-powered vulnerability validation, false-positive filtering, risk analysis.

1. Sign up at [https://platform.openai.com/signup](https://platform.openai.com/signup)
2. Go to [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
3. Create a new API key
4. New accounts get $5 free credit

Add to `config.yaml`:
```yaml
ai:
  openai_api_key: "sk-..."
```

Use with:
```bash
python main.py scan --target example.com --ai-provider openai
```

---

### Anthropic (Claude)

**Purpose:** AI-powered vulnerability validation using Claude models.

1. Sign up at [https://console.anthropic.com](https://console.anthropic.com)
2. Go to API Keys and create a new key
3. New accounts get $5 free credit

Add to `config.yaml`:
```yaml
ai:
  anthropic_api_key: "sk-ant-..."
```

Use with:
```bash
python main.py scan --target example.com --ai-provider anthropic
```

---

### Google Gemini

**Purpose:** AI-powered vulnerability validation using Gemini models.

1. Go to [https://aistudio.google.com](https://aistudio.google.com)
2. Click "Get API Key"
3. Free tier available

Add to `config.yaml`:
```yaml
ai:
  google_api_key: "AIza..."
```

Use with:
```bash
python main.py scan --target example.com --ai-provider gemini
```

---

### Chaos (ProjectDiscovery)

**Purpose:** Bug bounty program subdomain datasets (millions of pre-enumerated subdomains).

1. Go to [https://chaos.projectdiscovery.io](https://chaos.projectdiscovery.io)
2. Request access (free for security researchers)
3. Copy your API key

Add to `config.yaml`:
```yaml
api_keys:
  chaos: "your-chaos-api-key"
```

---

### GitHub Token

**Purpose:** GitHub dorking for secrets, API keys, and sensitive code in public repositories.

1. Go to [https://github.com/settings/tokens](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Select scopes: `public_repo`, `read:user`
4. Free — no usage limits for public repo search

Add to `config.yaml`:
```yaml
api_keys:
  github_token: "ghp_..."
```

Use with:
```bash
python main.py scan --target example.com --git-dork
```

---

## Using Environment Variables

All API keys can also be set via environment variables:

```bash
export GODRECON__API_KEYS__SHODAN="your-key"
export GODRECON__API_KEYS__VIRUSTOTAL="your-key"
export GODRECON__API_KEYS__SECURITYTRAILS="your-key"
export GODRECON__AI__OPENAI_API_KEY="sk-..."
```

This is useful for CI/CD environments or when you don't want to store keys in `config.yaml`.
