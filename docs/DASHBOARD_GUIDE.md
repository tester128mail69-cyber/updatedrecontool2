# Dashboard Guide

## Launching the Dashboard

```bash
# Start the GODRECON API server
python main.py api

# Access the dashboard
open http://127.0.0.1:8000/dashboard/

# API documentation
open http://127.0.0.1:8000/docs
```

To bind to all interfaces (for remote access):
```bash
python main.py api --host 0.0.0.0 --port 8000
```

---

## Sidebar Navigation

| Section | Page | Description |
|---------|------|-------------|
| **Main** | Dashboard | Overview — scan counts, severity summary, recent activity |
| **Main** | Scans | Start new scans, view scan history |
| **Main** | Targets | Manage your target list |
| **Main** | Findings | All vulnerability findings, sortable by severity |
| **Main** | Subdomains | Complete subdomain enumeration results |
| **Main** | Vulnerabilities | P1–P5 vulnerability details |
| **Main** | Secrets | JS secrets and leaked credentials |
| **Main** | Activity Log | Audit trail of all actions |
| **Analytics** | Analytics | Charts, trends, statistics |
| **Analytics** | Leaderboard | Top targets by finding count |
| **Analytics** | Attack Surface | Visual attack surface map |
| **Scanners** | AI Validation | AI-powered false-positive filtering |
| **Scanners** | Bounty Matcher | Match findings to bug bounty programs |
| **Scanners** | Chains | Auto-chained vulnerability paths |
| **Scanners** | Scan Detail | Deep-dive into a single scan |
| **Power** | Reports | Generate and download reports |
| **Power** | Alerts | Monitoring alerts and notifications |
| **Power** | Kanban | Drag-and-drop findings board |
| **Power** | Settings | API keys, notifications, preferences |

---

## Key Features

### Starting a Scan

1. Click **Scans** in the sidebar
2. Click **New Scan**
3. Enter target domain
4. Choose scan mode (Quick / Standard / Deep)
5. Click **Start Scan**

Progress updates appear in real-time on the scan detail page.

### Filtering Findings

On the **Findings** page:
- Filter by severity (P1 Critical → P5 Info)
- Filter by module (subdomains, vulns, secrets, etc.)
- Search by keyword
- Sort by date, severity, or confidence score

### Generating Reports

1. Go to **Reports**
2. Select a completed scan
3. Choose format: HTML, PDF, Markdown, JSON, HackerOne, Bugcrowd
4. Click **Generate** and download

### Setting Up Alerts

1. Go to **Settings** → **Notifications**
2. Enter your Slack/Discord/Telegram webhook URLs
3. Go to **Alerts** to see triggered alerts
4. Configure alert rules (new P1 finding, new subdomain, etc.)

### Global Search

Press `Ctrl+K` from anywhere in the dashboard to open the global search modal. Search across targets, findings, scans, and pages instantly.

### Dark / Light Theme

Click the 🌙 moon icon in the top-right header to toggle between dark and light themes.

---

## All 70 Dashboard Features

### Core (10)
1. Live scan progress with real-time updates
2. Multi-target management
3. Scan history and result storage
4. Start/stop/pause scans from UI
5. REST API with full OpenAPI docs
6. WebSocket live updates
7. Scan queue management
8. Scan scheduling from UI
9. Module-level progress tracking
10. Scan resume support

### Visual & UX (10)
11. Dark/light theme toggle
12. Responsive sidebar navigation
13. Global search (Ctrl+K)
14. Toast notifications
15. Rich data tables with sorting
16. Column filtering on all tables
17. Pagination with configurable page size
18. Breadcrumb navigation
19. Keyboard shortcuts
20. Mobile-responsive layout

### Productivity (10)
21. Kanban-style findings board
22. Bulk actions on findings (dismiss, mark, export)
23. CSV/JSON/HTML/PDF export
24. Report generation wizard
25. Scheduled scan management
26. Quick filters and saved searches
27. Target tagging and grouping
28. Notes on findings
29. Finding status tracking (open, in-progress, resolved)
30. Copy-to-clipboard for commands and payloads

### Analytics (10)
31. Findings severity breakdown (pie chart)
32. Subdomain growth over time (line chart)
33. Vulnerability trend charts
34. Module performance metrics
35. Leaderboard view (top targets by findings)
36. Scan duration statistics
37. Finding confidence distribution
38. Attack surface metrics
39. New vs. resolved findings comparison
40. Export analytics as PNG/SVG

### Security (10)
41. API key authentication
42. CORS configuration
43. Rate limiting
44. Audit log / activity feed
45. Session management
46. IP allowlisting (via config)
47. Findings access control
48. Report watermarking
49. Sensitive data masking
50. Secure webhook delivery

### WOW Factor (10)
51. Attack surface visualization
52. Interactive findings timeline
53. AI validation panel
54. Bug bounty matcher UI
55. Secrets explorer
56. Vulnerability chain viewer
57. Scan diff UI
58. Real-time alert feed
59. CVSS score calculator
60. PoC snippet viewer

### Scanner Panels (5)
61. Subdomain enumeration panel
62. Vulnerability findings panel
63. Port scan results with banners
64. Technology fingerprint view
65. Cloud misconfiguration panel

### Power Features (5)
66. Continuous monitoring dashboard
67. Alert management with rules
68. Webhook configuration
69. Multi-region scan control
70. Bulk scan launcher
