# ASRCE — Attack Surface Recon & Classification Engine

> Automated subdomain discovery, enrichment, and risk classification pipeline.

---

## What is ASRCE?

ASRCE is a multi-stage recon pipeline that maps an organization's full attack surface automatically. It discovers subdomains, enriches them with DNS and HTTP data, and classifies each one by risk level — so you know exactly where to look first.

Most recon tools dump a raw list and leave you to figure out what matters. ASRCE tells you what matters and why.

---

## Pipeline

```
Target Domain
     ↓
[1] Orchestration    — Subfinder + Amass in parallel
     ↓
[2] Normalization    — Deduplicate, validate, wildcard detection
     ↓
[3] Enrichment       — DNS (dnsx) + HTTP (httpx) analysis
     ↓
[4] Risk Scoring     — CRITICAL / HIGH / MEDIUM / LOW classification
     ↓
[5] JSON Report      — output/report_<domain>.json
```

---

## Installation

```bash
git clone https://github.com/Ume-Habiba-0x/ASRCE.git
cd ASRCE
pip install -r requirements.txt
```

**Required tools:**

```bash
# Install Go first if not already installed
sudo apt install golang-go -y

# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Amass
sudo apt install amass -y
```

Add Go binaries to PATH:

```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## Usage

```bash
# Full scan
python3 main.py -d target.com

# Full scan with minimal output
python3 main.py -d target.com --silent

# Re-classify existing scan data without re-scanning
python3 main.py --report-only
```

---

## Output

Each scan generates a structured JSON report at `output/report_<domain>.json`

```json
{
  "meta": {
    "tool": "ASRCE v2.0",
    "generated_at": "2026-01-01T00:00:00+00:00"
  },
  "summary": {
    "total": 45,
    "critical": 1,
    "high": 8,
    "medium": 28,
    "low": 8
  },
  "critical": [
    {
      "host": "staging.example.com",
      "ip": ["192.0.2.1"],
      "cname": ["example.herokuapp.com"],
      "risk": "CRITICAL",
      "reasons": ["Potential subdomain takeover → herokuapp.com"]
    }
  ],
  "high": [
    {
      "host": "dev.example.com",
      "ip": ["192.0.2.2"],
      "cname": [],
      "risk": "HIGH",
      "reasons": [
        "Direct IP exposure — no CDN or WAF protection",
        "Sensitive keyword 'dev' — not behind CDN"
      ]
    }
  ]
}
```

---

## Risk Classification

| Risk | Criteria |
|------|----------|
| CRITICAL | Subdomain takeover potential, expired TLS certificate |
| HIGH | Direct IP exposure, sensitive keyword without CDN, weak TLS |
| MEDIUM | Live host behind CDN, outdated tech stack, internal CNAME alias |
| LOW | Live host behind real CDN, no significant issues |

---

## Edge Cases Handled

| Priority | Issue | Solution |
|----------|-------|----------|
| CRITICAL | Wildcard DNS | Pattern detection — flags domains with 50+ matching subdomains |
| HIGH | Rate limiting | Request throttling + amass timeout fallback |
| HIGH | HTTP/HTTPS mismatch | Both protocols checked before marking host dead |
| MEDIUM | CNAME chain | Full chain traversal in enricher |
| LOW | Load balancer IPs | Filtered from risk output |

---

## Project Structure

```
ASRCE/
├── main.py                  # Entry point
├── requirements.txt
├── modules/
│   ├── orchestrator.py      # Parallel subdomain discovery
│   ├── normalizer.py        # Dedup, validation, wildcard detection
│   ├── enricher.py          # DNS + HTTP enrichment
│   ├── risk_scorer.py       # Risk classification engine
│   └── output.py            # Reserved for future export formats
├── data/                    # Generated at runtime
├── output/                  # Reports generated at runtime
└── docs/
    ├── architecture.md
    ├── decisions.md
    └── edge_cases.md
```

---

## Legal

> Only run against targets you own or have explicit written permission to test.
>
> Legal practice targets: `scanme.nmap.org`, HackTheBox machines, your own VPS, bug bounty program targets within defined scope.

---

## Documentation

- [Architecture](docs/architecture.md) — pipeline design and module breakdown
- [Design Decisions](docs/decisions.md) — why each decision was made
- [Edge Cases](docs/edge_cases.md) — what breaks naive tools and how ASRCE handles it