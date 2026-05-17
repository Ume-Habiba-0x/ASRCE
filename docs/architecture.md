```markdown
# ASRCE — Architecture

## Overview

ASRCE is a 5-stage sequential pipeline. Each stage produces output that feeds the next. No stage is skipped.

## Pipeline Flow

```
Target Domain
     ↓
[1] Orchestrator   — modules/orchestrator.py
     ↓
[2] Normalizer     — modules/normalizer.py
     ↓
[3] Enricher       — modules/enricher.py
     ↓
[4] Risk Scorer    — modules/risk_scorer.py
     ↓
[5] JSON Report    — output/report_<domain>.json
```

## Module Breakdown

### orchestrator.py
Runs Subfinder and Amass simultaneously using Python threading.
Both tools use different data sources — Subfinder hits certificate
transparency logs, Amass does passive DNS enumeration.
Parallel execution reduces discovery time significantly.
Output: data/subdomains_raw.txt

### normalizer.py
Takes raw subdomain list and cleans it.
- Removes duplicates across both tool outputs
- Validates each entry matches real domain format using regex
- Detects wildcard DNS — if 50+ subdomains share same base, flags it
Output: data/subdomains_clean.txt

### enricher.py
Two-stage enrichment:
- dnsx: resolves DNS records, finds IPs and CNAME chains
- httpx: probes live hosts for HTTP status, web server, TLS, CDN
Output: data/dns_results.json + data/http_results.json

### risk_scorer.py
Merges DNS and HTTP data per host.
Classifies each into CRITICAL / HIGH / MEDIUM / LOW based on:
- Subdomain takeover potential (CNAME to unclaimed service)
- TLS certificate expiry or weakness
- Direct IP exposure (no CDN or WAF)
- Sensitive keywords in subdomain name
- Tech stack fingerprinting
Output: output/report_<domain>.json

## Data Flow Between Stages

```
subdomains_raw.txt
       ↓
subdomains_clean.txt
       ↓
dns_results.json + http_results.json
       ↓
report_<domain>.json
```

## Design Principles

- Each stage is independently testable
- Pipeline is resumable — any stage can be re-run on existing data
- Output is always structured JSON — never raw text dumps
- Risk escalates but never downgrades within one host
```

 