# ASRCE — Edge Cases

What breaks naive recon tools — and how ASRCE handles each one.

---

## CRITICAL: Wildcard DNS

**What it is:** Some domains configure `*.target.com` to resolve for any subdomain, even ones that don't exist as real services.

**Why it breaks naive tools:** A bruteforce scanner sees every subdomain resolve and reports thousands of "discoveries" — all noise.

**How ASRCE handles it:** The normalizer counts how many subdomains share the same base domain. If more than 50 resolve, it flags a wildcard DNS warning before enrichment runs. The operator can decide whether to continue or adjust scope.

---

## HIGH: Rate Limiting

**What it is:** Targets or DNS resolvers detect high-volume queries and block the source IP mid-scan.

**Why it breaks naive tools:** The scan silently stops producing results. The operator doesn't know if they got everything or got cut off halfway.

**How ASRCE handles it:** Amass has a built-in `-timeout` flag limiting its run time. Python's subprocess timeout acts as a safety net. Future versions will add request throttling and randomized timing between queries.

---

## HIGH: HTTP/HTTPS Mismatch

**What it is:** A subdomain returns nothing on `http://` but is fully alive on `https://` — or vice versa.

**Why it breaks naive tools:** Tools that only check one protocol mark the host as dead and skip it entirely.

**How ASRCE handles it:** httpx checks both protocols by default. A host is only marked dead if both return no response.

---

## MEDIUM: CNAME Chain

**What it is:** A subdomain points to a CNAME, which points to another CNAME, which points to an unclaimed third-party service. One-hop DNS checks miss the takeover.

**Example:**
sub.target.com → app.herokuapp.com → [unclaimed]
**Why it breaks naive tools:** Single-hop DNS resolution stops at the first CNAME and misses that the final destination is unclaimed.

**How ASRCE handles it:** dnsx follows the full CNAME chain and returns all hops. The risk scorer checks every CNAME in the chain against the known takeover services list.

---

## LOW: Load Balancer IPs

**What it is:** Multiple subdomains resolve to the same IP address because they share load balancer infrastructure.

**Why it confuses naive tools:** Tools that flag shared IPs as anomalies produce false positives — this is normal infrastructure, not a vulnerability.

**How ASRCE handles it:** Shared IPs are not flagged as risks. The risk scorer evaluates each subdomain independently based on its own signals, not IP uniqueness.

---

## Known Limitations

- Wildcard detection uses a count threshold (50+) which may miss low-volume wildcards
- Rate limiting protection is partial — full throttling is a planned v2 feature
- CNAME takeover detection relies on a static list of known vulnerable services — new services require manual list updates
- Tech stack fingerprinting depends on httpx detection accuracy