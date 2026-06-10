# ASRCE — How It Works

Every stage explained. What runs, what it produces, what decisions it makes, and what can go wrong.

---

## The Problem This Solves

Running `subfinder -d target.com` gives you a list. It tells you nothing about which subdomains matter, which are protected, which have expired certificates, or which are directly exposed to attackers.

ASRCE adds the layer that's missing — enrichment and classification. The output is not a list. It's a ranked report that tells you what to look at first and why.

---

## Pipeline Overview
Target Domain
↓
[1] Orchestration   — parallel subdomain discovery
↓
[2] Normalization   — clean, validate, detect wildcards
↓
[3] Enrichment      — DNS → alive filter → HTTP → WAF
↓
[4] Risk Scoring    — deterministic CRITICAL/HIGH/MEDIUM/LOW
↓
[5] Output          — JSON report + HTML dashboard + log file

Each stage passes data directly to the next as Python objects — not via intermediate files. If a stage returns empty results, the pipeline halts immediately with a clear error message instead of silently producing a garbage report.

---

## Stage 1 — Orchestration

**File:** `modules/orchestrator.py`
**Mode:** Fully passive
**Time:** 1–2 minutes depending on target size

### What runs

Two tools execute simultaneously in parallel OS threads:

- **Subfinder** — queries certificate transparency logs, passive DNS databases, VirusTotal, and other OSINT sources. Fast, broad coverage.
- **Amass** — passive enumeration mode, different data sources than Subfinder. Adds coverage Subfinder misses.

Running both in parallel means total time equals whichever tool takes longer — not the sum of both.

### What it produces

Every discovered subdomain is stored in an intelligence map — not a flat list:

```json
{
  "mail.target.com": {
    "sources": ["subfinder", "amass"],
    "confidence": 2
  },
  "dev.target.com": {
    "sources": ["subfinder"],
    "confidence": 1
  }
}
```

**Confidence score** — how many independent tools found this subdomain. A subdomain found by both subfinder and amass is more likely to be real than one found by only one tool. This carries forward into the final risk report.

### What can go wrong

- Amass times out on large targets — pipeline continues with subfinder results only, logs a warning
- Subfinder returns 0 results — pipeline halts with exit code 2, no wasted cycles
- Network drops mid-scan — results collected so far are preserved, interrupt message shows the resume command

---

## Stage 2 — Normalization

**File:** `modules/normalizer.py`
**Mode:** CPU-only, no network
**Time:** Instant

### What runs

Raw tool output is dirty. This stage cleans it.

**Deduplication** — both tools may find the same subdomain. Set deduplication removes duplicates while the intelligence map preserves which tools found what.

**Domain validation** — each entry is checked against strict rules:
- Must match FQDN format
- Labels must be ≤63 characters
- No wildcards (`*.target.com`)
- No IP addresses
- No single-label entries

Weak filters like `"." in line` accept garbage. ASRCE rejects anything that doesn't look like a real domain.

**Wildcard DNS detection** — if 50+ subdomains share the same base domain, wildcard DNS is likely configured. This means `random123.target.com` resolves even though it doesn't exist as a real service. The pipeline flags this so the operator knows the results may contain noise.

### What it produces

A clean, validated list of subdomains ready for enrichment. The intelligence map from Stage 1 is preserved — confidence scores survive normalization.

---

## Stage 3 — Enrichment

**File:** `modules/enricher.py`
**Mode:** Active network probing
**Time:** 2–5 minutes depending on alive host count

This is the most complex stage. Three tools run in sequence, each feeding the next.

### Step 1 — DNS resolution (dnsx)

dnsx resolves every subdomain and returns:
- **A records** — the actual IP addresses
- **CNAME chains** — the full alias chain, not just one hop
- **Status** — NOERROR (resolves) or NXDOMAIN (doesn't exist)

Configuration:
- 50 concurrent threads — fast without triggering rate limits
- 4 DNS resolvers in rotation — Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9), OpenDNS (1.0.0.1). Spreading queries across resolvers means no single resolver sees enough volume to block the scan.

### Step 2 — Alive host filtering

Before HTTP probing, ASRCE filters to only hosts that have real A records and NOERROR status.

On a tested target this reduced probes from 100 subdomains to 69 alive hosts. httpx only runs on those 69. Dead subdomains get no HTTP probe — they carry their DNS data into the risk scorer but skip HTTP enrichment.

This matters because httpx is expensive — each probe is a real HTTP connection with TLS handshake. Probing dead subdomains wastes time and generates noise.

### Step 3 — HTTP probing (httpx)

httpx probes each alive host and returns:
- HTTP status code
- Web server header
- Page title
- Technology stack (framework, CMS, server version)
- CDN detection
- Full TLS certificate data (version, expiry date, issuer, subject)

Configuration:
- User agent rotation — each request uses a different browser user agent string
- 30 second timeout — slow hosts don't stall the entire scan
- Both HTTP and HTTPS checked — a host that returns nothing on port 80 may be fully alive on port 443

### Step 4 — WAF detection (wafw00f)

wafw00f fingerprints WAF presence by analyzing response patterns, error pages, and header signatures.

If wafw00f is not installed, ASRCE falls back to header-based detection:
- `cf-ray` header → Cloudflare
- `x-akamai-transformed` → Akamai
- `x-cdn: imperva` → Imperva
- Server header `cloudflare` → Cloudflare

The tool never silently skips WAF detection — if the binary is missing, header matching runs instead.

---

## Stage 4 — Risk Scoring

**File:** `modules/risk_scorer.py`
**Mode:** CPU-only, no network
**Time:** Instant

### How classification works

Every host starts at LOW. The scorer applies checks in order and escalates risk — it never downgrades. If a host triggers HIGH, a MEDIUM finding on the same host does not lower it.

**CRITICAL triggers:**
- CNAME points to an unclaimed third-party service (amazonaws.com, herokuapp.com, github.io, netlify.app, etc.) — potential subdomain takeover
- TLS certificate is expired

**HIGH triggers:**
- Direct IP exposure — host has an A record but no CNAME, meaning no CDN or WAF sits in front of it
- Sensitive keyword in subdomain name (`dev`, `admin`, `staging`, `backup`, `db`, `vpn`, etc.) without CDN protection
- Weak TLS version — TLS 1.0 or 1.1
- Certificate expires within 30 days

**MEDIUM triggers:**
- Sensitive keyword present but host is behind a CDN
- Outdated tech stack — IIS 6/7/8, ASP.NET 3.x/4.0
- TLS 1.2 (TLS 1.3 preferred)
- HTTP 500/502/503 publicly exposed
- Live host with internal CNAME alias (not a real CDN)

**LOW:**
- Live host behind a real CDN with TLS 1.3 and no significant issues

### Cloudflare A-record detection

Some targets deploy Cloudflare via A records pointing directly to Cloudflare IPs rather than CNAMEs. A naive check — "has no CNAME = direct IP exposure" — would falsely flag these as HIGH.

ASRCE validates against Cloudflare's anycast IP ranges:
- `104.16.0.0/12` (104.16.x.x – 104.31.x.x)
- `172.64.0.0/13` (172.64.x.x – 172.71.x.x)

If the A record falls in these ranges, the host is correctly identified as behind Cloudflare — not a direct IP exposure.

---

## Stage 5 — Output

**Files:** `modules/html_reporter.py`, `modules/risk_scorer.py`

Every scan produces three artifacts:

**JSON report** — `output/report_<domain>.json`
Structured, machine-readable. Contains full metadata per host — IP, CNAME chain, status, web server, TLS summary, WAF, risk level, reasons, source attribution, confidence score.

**HTML dashboard** — `output/report_<domain>.html`
Interactive Chart.js visualization. Donut chart showing severity distribution. Filter buttons for CRITICAL/HIGH/MEDIUM/LOW. Per-finding cards with all enrichment data. Readable in any browser, no server required.

**Log file** — `data/logs/<domain>_<timestamp>.log`
Full timestamped execution log. Every subprocess command, every result count, every error.

---

## Edge Cases

| Issue | What breaks without handling | How ASRCE handles it |
|-------|------------------------------|----------------------|
| Wildcard DNS | Thousands of fake subdomains flood the pipeline | Count-based detection — flags base domains with 50+ subdomains |
| Rate limiting | DNS resolver blocks mid-scan, silent data loss | Resolver rotation across 4 providers |
| Wrong httpx binary | System httpx has different flags than ProjectDiscovery httpx | Full path via `GO_BIN` environment variable |
| httpx exit code 1 | Strict exit code check aborts on partial failure | Accept exit codes 0 and 1 — process whatever output was produced |
| HTTP/HTTPS mismatch | Host alive on 443 but dead on 80 — marked dead incorrectly | httpx checks both protocols by default |
| wafw00f missing | WAF detection silently skipped | Header signature fallback always runs |
| Cloudflare A-record | Host behind Cloudflare flagged as direct IP exposure | IP-range validation against Cloudflare anycast networks |
| Tool binary not found | Pipeline crashes with unhelpful error | Graceful skip with logged warning, pipeline continues |
| Empty orchestration result | Normalization runs on empty file, produces empty output | Pipeline halts with exit code 2 if no subdomains found |

---

## Known Limitations

**Resume is not fully implemented.** The `--resume` flag exists and the interrupt handler shows the resume command, but stage-skipping logic is not yet built. Restarting with `--resume` currently reruns the full pipeline.

**Confidence scoring is single-source on most targets.** Amass frequently times out, meaning most subdomains show confidence 1 (subfinder only). The infrastructure is in place — it works correctly when amass contributes results.

**wafw00f runs on DNS-alive hosts, not HTTP-alive hosts.** This means wafw00f probes some hosts that didn't respond to HTTP. Fix in progress.

**No API key support.** Subfinder supports API keys for VirusTotal, Shodan, and other sources. Without keys, some passive DNS sources are unavailable. Adding API key configuration is on the roadmap.
