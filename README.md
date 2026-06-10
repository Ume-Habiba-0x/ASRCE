 
<h1 align="center">
  <br>
  ASRCE
  <br>
</h1>

<h4 align="center">Attack Surface Recon & Classification Engine</h4>

<p align="center">
  <img src="https://img.shields.io/badge/version-v2.0-0891B2?style=for-the-badge" alt="version v2.0">
  <img src="https://img.shields.io/badge/python-3.10+-3572A5?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/pipeline-4_stages-059669?style=for-the-badge" alt="4 stages">
  <img src="https://img.shields.io/badge/license-MIT-DC2626?style=for-the-badge" alt="MIT license">
  <img src="https://img.shields.io/badge/platform-Kali_Linux-557C94?style=for-the-badge&logo=linux&logoColor=white" alt="Kali Linux">
</p>

<p align="center">
  <b>One command → Ranked attack surface intelligence</b><br>
  4 stages · Source attribution · Confidence scoring · Interactive HTML report
</p>

<p align="center">
  <a href="#the-problem-it-solves">Problem</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#output">Output</a> •
  <a href="#real-world-validation">Validation</a>
</p>
<!-- markdownlint-enable MD033 MD045 -->

---

## The Problem It Solves

Running `subfinder -d target.com` gives you a list. It tells you nothing about which subdomains matter, which are protected, which have expired certificates, or which are directly exposed to attackers.

Before ASRCE, a recon session looked like this — run subfinder, get 500 subdomains, manually cross-reference with dnsx, pipe into httpx, lose track of which tool found what, end up with 15 disconnected text files. Two hours before you even started testing anything.

ASRCE collapses that into one command. It discovers, validates, enriches, and automatically ranks every host by risk.

```bash
python3 main.py -d target.com
```

---

## Features

### Discovery
- Subfinder + amass run simultaneously in parallel threads
- Source attribution — every subdomain tracks which tool found it
- Confidence scoring — found by 1 tool = LOW, 2 tools = MEDIUM
- Rate limiting via `-rl` flag
- DNS resolver rotation — 4 resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9, 1.0.0.1)

### Normalization
- Strict domain validation — label length, hyphen rules, no wildcards, no IPs
- Deduplication without losing source metadata
- Wildcard DNS detection — flags domains with 50+ matching subdomains

### Enrichment
- Alive-host filtering — DNS resolution before HTTP probing
- dnsx — full A/CNAME chain resolution
- httpx — status, title, tech stack, CDN, TLS certificate data
- wafw00f — active WAF fingerprinting with header signature fallback
- User-agent rotation per request
- 30 second HTTP timeout, 50 thread cap

### Risk Scoring
- CRITICAL / HIGH / MEDIUM / LOW — deterministic, no guesswork
- Risk escalates but never downgrades within one host
- Cloudflare A-record detection via IP-range validation

---

## Architecture

```
Target Domain
     │
     ▼
┌─────────────────────────────────────────┐
│  [1] ORCHESTRATION                      │
│      subfinder + amass (parallel)       │
│      • Rate limiting (-rl)              │
│      • DNS resolver rotation            │
│      • Source attribution per host      │
│      • Confidence scoring (1–3)         │
└─────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────┐
│  [2] NORMALIZATION                      │
│      • Strict domain validation         │
│      • Deduplication                    │
│      • Wildcard DNS pattern detection   │
└─────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────┐
│  [3] ENRICHMENT                         │
│      dnsx: A/CNAME/RESP resolution      │
│      httpx: Status, Title, Tech, CDN,   │
│             TLS-grab, UA rotation       │
│      wafw00f: Active WAF fingerprinting │
│      • Alive-host filtering before HTTP │
│      • Thread cap (50) + HTTP timeout   │
└─────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────┐
│  [4] RISK SCORING                       │
│      Deterministic classification:      │
│      CRITICAL / HIGH / MEDIUM / LOW     │
│      • Subdomain takeover detection     │
│      • TLS expiry & version analysis    │
│      • Direct IP exposure logic         │
│      • Cloudflare IP-range detection    │
│      • Sensitive keyword + CDN check    │
│      • Tech-stack aging detection       │
└─────────────────────────────────────────┘
     │
     ▼
  JSON Report + HTML Dashboard + Log File
```

---

## Risk Classification Matrix

| Severity | Trigger Conditions |
|----------|--------------------|
| **CRITICAL** | Expired TLS certificate; dangling CNAME to unclaimed service (amazonaws, herokuapp, github.io) |
| **HIGH** | Direct IP exposure no CDN or WAF; sensitive keyword without CDN; weak TLS 1.0/1.1; cert expires within 30 days |
| **MEDIUM** | Sensitive keyword behind CDN; outdated tech (IIS 6–8, ASP.NET 3.x–4.0); TLS 1.2; internal CNAME alias; HTTP 500/502/503 |
| **LOW** | Live host behind real CDN with TLS 1.3, no significant issues |

---

## Installation

### Prerequisites

```
# Go toolchain
sudo apt install golang-go -y

# Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### External Binaries

```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
pip install wafw00f

# Add Go binaries to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
echo 'export GO_BIN=$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## Usage

```
# Full scan
python3 main.py -d target.com

# Re-classify existing data without re-scanning
python3 main.py --report-only

# Silent mode
python3 main.py -d target.com --silent
```

---

## Output

Every scan produces three artifacts:

```
output/report_<domain>.json     — structured machine-readable report
output/report_<domain>.html     — interactive Chart.js dashboard
data/logs/<domain>_<ts>.log     — full timestamped execution log
```

### HTML Dashboard
- Dark theme, severity-colored cards
- Donut chart — instant visual breakdown
- Filter tabs — CRITICAL / HIGH / MEDIUM / LOW
- Per-host cards — IP, CNAME, status, server, TLS, WAF, reasons
- Source attribution and confidence labels

---

## Real-World Validation

### Target A — Mixed infrastructure domain
Passive recon via public certificate transparency logs and DNS records only.

| Metric | Value |
|--------|-------|
| Subdomains discovered | 100 |
| Alive hosts | 69 |
| CRITICAL | 5 |
| HIGH | 33 |
| MEDIUM | 27 |
| LOW | 4 |
| Scan time | ~4 minutes |

Notable findings:
- Expired TLS certificate cluster — 5 subdomains sharing one expired certificate indicating systemic configuration drift
- Multiple production hosts on EOL framework with direct IP exposure
- Internal RFC1918 IPs leaking via public DNS CNAME chains

### Target B — vulnweb.com (Acunetix intentional test target)

| Metric | Value |
|--------|-------|
| Subdomains discovered | 20 |
| Alive hosts | 6 |
| HIGH | 6 |
| Scan time | ~2 minutes |

Notable findings:
- Apache 2.4.25 EOL with PHP 7.1.26 EOL, direct IP exposure
- IIS 8.5 EOL 2018, direct IP exposure

---

## Project Structure

```
ASRCE/
├── main.py
├── requirements.txt
├── modules/
│   ├── orchestrator.py      # Parallel discovery + confidence scoring
│   ├── normalizer.py        # Validation + wildcard detection
│   ├── enricher.py          # DNS → HTTP → WAF chain
│   ├── risk_scorer.py       # Deterministic classification engine
│   ├── state_manager.py     # State tracking
│   └── html_reporter.py     # Chart.js dashboard generator
├── data/
│   ├── logs/
│   ├── resolvers.txt
│   └── *.txt / *.json       # Intermediate data (gitignored)
├── docs/
│   ├── how-it-works.md
│   └── decisions.md
└── output/
    └── report_<domain>.json / .html
```

---

## Edge Cases Handled

| Issue | How ASRCE handles it |
|-------|----------------------|
| Wildcard DNS | Flags base domains with 50+ matching subdomains |
| Rate limiting | Resolver rotation across 4 providers + `-rl` flag |
| Wrong httpx binary | Full path via `GO_BIN` environment variable |
| httpx exit code 1 | Accepts codes 0 and 1 — processes partial output |
| HTTP/HTTPS mismatch | httpx checks both protocols before marking dead |
| wafw00f missing | Header signature fallback always runs |
| Cloudflare A-record | IP-range validation prevents false HIGH |
| Empty discovery result | Pipeline halts with exit code 2 |

---

## Roadmap

- [ ] Resume — stage-skipping logic for interrupted scans
- [ ] ASN-based CDN detection
- [ ] API key support for subfinder sources
- [ ] SQLite backend for multi-domain campaign tracking
- [ ] Async I/O rewrite for enrichment stage

---

## Legal

Only run ASRCE against targets you own or have explicit written permission to test.

Legal practice targets: `vulnweb.com`, `scanme.nmap.org`, HackTheBox machines, your own infrastructure, bug bounty program targets within defined scope.

---

## Author

Built by **[Ume Habiba](https://github.com/Ume-Habiba-0x)** — Offensive Security Practitioner, Security Researcher

---

## License

Released under the [MIT License](LICENSE). Contributions, improvements, and constructive feedback are welcome.
```

 
