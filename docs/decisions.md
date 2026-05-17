# ASRCE — Design Decisions

---

## 1. Parallel discovery

Sequential execution means total time = Subfinder + Amass. Parallel means whichever finishes last — significantly faster on large targets.

They also use different data sources, so running both gives wider coverage than either alone. The tradeoff is a threading lock on the shared results list to prevent race conditions.

---

## 2. Normalize before enriching

Raw tool output is dirty — duplicates, invalid strings, wildcard noise. The worst case is wildcard DNS: if `*.target.com` resolves everything, you get thousands of fake subdomains. Catching that early means dnsx and httpx don't waste time on noise.

---

## 3. dnsx + httpx over custom probing

Both are battle-tested, thread natively, and output structured JSON. ASRCE's value is in orchestration, normalization, and risk classification — the gaps existing tools don't fill. Reinventing probing isn't the point.

---

## 4. Keyword-based risk signals

`dev`, `admin`, `staging`, `backup` are signals, not proof. These endpoints are statistically more likely to have weaker controls. They get flagged for closer inspection, not auto-classified as vulnerable.

---

## 5. CRITICAL as a separate tier

Subdomain takeover is directly exploitable — claim the unclaimed service, serve content under the target's domain. That's categorically different from HIGH findings which are exposed but not immediately weaponizable.

---

## 6. Structured JSON output

Plain text is human-readable, not machine-readable. JSON reports can be piped into other tools, filtered by risk level, and stored per-target. ASRCE is designed to be composable — plain text kills that.

---

## 7. Per-domain report files

A single `report.json` gets overwritten every scan. `report_<domain>.json` means you can run against multiple targets, keep all results, and compare them.

---

## 8. `--report-only` mode

Discovery and enrichment are slow. If you tweak scoring logic, re-running the full pipeline to test it is wasteful. This flag re-runs classification on existing data only.