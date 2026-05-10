import json

# Keywords that signal sensitive/risky subdomains
HIGH_RISK_KEYWORDS = [
    "dev", "staging", "stg", "admin", "backup", "test", "internal",
    "vpn", "ftp", "ssh", "jenkins", "gitlab", "jira", "confluence",
    "debug", "uat", "qa", "sandbox", "api", "gateway"
]

TAKEOVER_SERVICES = [
    "amazonaws.com", "herokuapp.com", "github.io", "netlify.app",
    "vercel.app", "surge.sh", "fastly.net", "ghost.io"
]

def has_high_keyword(host):
    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in host.lower():
            return True
    return False

def is_potential_takeover(record):
    cnames = record.get("cname", [])
    for cname in cnames:
        for service in TAKEOVER_SERVICES:
            if service in cname:
                return True
    return False

def is_direct_ip(record):
    # has A record but no CNAME = directly exposed server
    has_a = bool(record.get("a"))
    has_cname = bool(record.get("cname"))
    return has_a and not has_cname

def classify(record):
    host = record.get("host", "")
    status = record.get("status_code", "")

    # skip dead subdomains
    if status == "NXDOMAIN":
        return None

    risk = "LOW"
    reasons = []

    # HIGH: direct IP exposure
    if is_direct_ip(record):
        risk = "HIGH"
        reasons.append("Direct IP — no CDN/WAF protection")

    # HIGH: potential takeover
    if is_potential_takeover(record):
        risk = "HIGH"
        reasons.append("Potential subdomain takeover")

    # HIGH: sensitive keyword + no WAF
    if has_high_keyword(host) and not record.get("cname"):
        risk = "HIGH"
        reasons.append(f"Sensitive keyword in subdomain")

    # MEDIUM: has CDN but sensitive keyword
    if risk == "LOW" and has_high_keyword(host):
        risk = "MEDIUM"
        reasons.append("Sensitive keyword but behind CDN")

    # MEDIUM: alive with CNAME chain (CDN protected)
    if risk == "LOW" and record.get("cname"):
        risk = "MEDIUM"
        reasons.append("Live host behind CDN")

    return {
        "host": host,
        "ip": record.get("a", []),
        "cname": record.get("cname", []),
        "status": status,
        "risk": risk,
        "reasons": reasons
    }

def run_risk_scorer(
    input_file="data/dns_results.json",
    output_file="output/report.json"
):
    print("[*] Running risk classification...")

    try:
        with open(input_file, "r") as f:
            records = json.load(f)
    except FileNotFoundError:
        print("[-] No DNS results found. Run enricher first.")
        return

    high, medium, low = [], [], []

    for record in records:
        result = classify(record)
        if result is None:
            continue
        if result["risk"] == "HIGH":
            high.append(result)
        elif result["risk"] == "MEDIUM":
            medium.append(result)
        else:
            low.append(result)

    report = {
        "summary": {
            "total": len(high) + len(medium) + len(low),
            "high": len(high),
            "medium": len(medium),
            "low": len(low)
        },
        "high": high,
        "medium": medium,
        "low": low
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'='*50}")
    print(f"  ASRCE RISK REPORT")
    print(f"{'='*50}")
    print(f"  HIGH   : {len(high)}")
    print(f"  MEDIUM : {len(medium)}")
    print(f"  LOW    : {len(low)}")
    print(f"{'='*50}")
    print(f"[+] Report saved → {output_file}")

    # print HIGH findings immediately
    if high:
        print("\n[!] HIGH RISK FINDINGS:")
        for h in high:
            print(f"  → {h['host']}")
            for r in h['reasons']:
                print(f"    • {r}")