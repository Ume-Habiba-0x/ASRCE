# ASRCE — Design Decisions

Every architectural decision in ASRCE has a reason. This document explains the thinking behind each one.

---

## 1. Why parallel execution for discovery?

**Decision:** Run Subfinder and Amass simultaneously using Python threading.

**Why:** Sequential execution means total time = Subfinder time + Amass time. Parallel means total time = whichever finishes last. On large targets this cuts discovery time significantly.

**Why both tools?** Each uses different data sources. Subfinder queries certificate transparency logs and passive DNS databases. Amass does broader enumeration. Running both gives wider coverage than either alone.

**Tradeoff:** Threading adds complexity. A shared results list requires a lock to prevent race conditions when both threads write simultaneously.

---

## 2. Why normalize before enriching?

**Decision:** Deduplicate and validate subdomains before passing to dnsx or httpx.

**Why:** Raw tool output is dirty. It can contain duplicates from both tools finding the same subdomain, invalid strings like error messages or headers, and wildcard DNS noise. Feeding dirty input into dnsx wastes time and produces misleading results.

**Wildcard DNS specifically:** If `*.target.com` resolves everything, bruteforce produces thousands of fake subdomains. Detecting this pattern early prevents wasted enrichment on noise.

---

## 3. Why dnsx + httpx instead of writing our own DNS/HTTP checks?

**Decision:** Use ProjectDiscovery's dnsx and httpx instead of building DNS and HTTP probing from scratch.

**Why:** dnsx and httpx are battle-tested, handle edge cases, support threading natively, and output structured JSON. Building equivalent functionality from scratch would take weeks and still be less reliable. The right engineering decision is tool composition over reinvention.

**What ASRCE adds:** The orchestration layer, normalization, and risk classification. These are the gaps that existing tools don't fill.

---

## 4. Why keyword-based risk scoring?

**Decision:** Flag subdomains containing words like dev, admin, staging, backup as higher risk.

**Why:** These keywords indicate internal or sensitive infrastructure that is likely not intended to be publicly accessible. A subdomain named `dev.target.com` is statistically more likely to have weaker security controls than `www.target.com`.

**Limitation acknowledged:** Keywords alone are not proof of vulnerability. They are signals that warrant closer inspection. This is documented as a known limitation.

---

## 5. Why CRITICAL as a separate severity level?

**Decision:** Add CRITICAL above HIGH for subdomain takeover and expired certificates.

**Why:** Subdomain takeover is directly exploitable — an attacker can register the unclaimed service and serve malicious content under the target's domain. This is categorically different from "exposed but protected" findings. It needed its own severity tier.

---

## 6. Why structured JSON output instead of plain text?

**Decision:** Every report is a structured JSON file named `report_<domain>.json`.

**Why:** Plain text output is human-readable but not machine-readable. JSON output can be piped into other tools, imported into dashboards, filtered by risk level programmatically, and stored per-target without overwriting previous results. This makes ASRCE composable in larger workflows.

---

## 7. Why per-domain report files?

**Decision:** Save reports as `output/report_<domain>.json` instead of a single `report.json`.

**Why:** A single output file gets overwritten every scan. Per-domain files let you run ASRCE against multiple targets and keep all results. Comparing `report_tesla.com.json` with `report_target.com.json` becomes possible.

---

## 8. Why --report-only mode?

**Decision:** Add a flag that skips discovery and enrichment, only re-runs classification on existing data.

**Why:** Discovery and enrichment are slow — minutes to hours depending on target size. If you want to tweak the risk scoring logic and re-classify existing results, re-running the full pipeline is wasteful. Report-only mode separates classification from data collection.