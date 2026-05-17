"""
ASRCE — Attack Surface Recon Classification Engine
Version 2.0
Author: Ume-Habiba
"""

import json
import os
from datetime import datetime, timezone

HIGH_RISK_KEYWORDS = [
    "dev", "staging", "stg", "admin", "backup", "test",
    "internal", "vpn", "ftp", "ssh", "jenkins", "gitlab",
    "jira", "confluence", "debug", "uat", "qa", "sandbox",
    "api", "gateway", "mgmt", "management", "panel", "cpanel",
    "phpmyadmin", "db", "database", "remote", "rdp"
]

TAKEOVER_SERVICES = [
    "amazonaws.com", "herokuapp.com", "github.io",
    "netlify.app", "vercel.app", "surge.sh",
    "fastly.net", "ghost.io", "azurewebsites.net",
    "cloudapp.net", "s3-website", "myshopify.com"
]

REAL_CDN_PROVIDERS = [
    "cloudflare.net", "akamaiedge.net", "fastly.net",
    "cloudfront.net", "azureedge.net", "edgekey.net",
    "akamai.net", "incapdns.net"
]

CERT_EXPIRY_WARNING_DAYS = 30


def has_high_keyword(host):
    host_lower = host.lower()
    for keyword in HIGH_RISK_KEYWORDS:
        if f".{keyword}." in f".{host_lower}." or host_lower.startswith(f"{keyword}."):
            return True, keyword
    return False, None


def is_potential_takeover(record):
    cnames = record.get("cname", [])
    for cname in cnames:
        for service in TAKEOVER_SERVICES:
            if service in cname.lower():
                return True, service
    return False, None


def is_direct_ip(record):
    has_a     = bool(record.get("a"))
    has_cname = bool(record.get("cname"))
    return has_a and not has_cname


def is_behind_real_cdn(record):
    cnames = record.get("cname", [])
    for cname in cnames:
        for cdn in REAL_CDN_PROVIDERS:
            if cdn in cname.lower():
                return True
    return False


def analyze_tls(record):
    findings = []
    tls = record.get("tls", {})
    if not tls:
        return findings
    if tls.get("expired"):
        findings.append(("CRITICAL", "TLS certificate is expired"))
    not_after = tls.get("not_after")
    if not_after and not tls.get("expired"):
        try:
            expiry_date = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            days_left   = (expiry_date - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(("CRITICAL", f"Certificate expired {abs(days_left)} days ago"))
            elif days_left <= CERT_EXPIRY_WARNING_DAYS:
                findings.append(("HIGH", f"Certificate expires in {days_left} days"))
        except Exception:
            pass
    tls_version = tls.get("tls_version", "")
    if tls_version in ["tls10", "tls11", "ssl30", "ssl20"]:
        findings.append(("HIGH", f"Weak TLS version: {tls_version.upper()}"))
    elif tls_version == "tls12":
        findings.append(("MEDIUM", "TLS 1.2 detected — TLS 1.3 preferred"))
    return findings


def analyze_tech_stack(record):
    findings = []
    for tech in record.get("tech", []):
        t = tech.lower()
        if "asp.net:4.0" in t or "asp.net:3." in t:
            findings.append(("MEDIUM", f"Outdated framework: {tech}"))
        if "iis:6" in t or "iis:7" in t or "iis:8" in t:
            findings.append(("MEDIUM", f"Outdated web server: {tech}"))
        if "php" in t:
            findings.append(("INFO", f"PHP detected: {tech}"))
    return findings


def analyze_http(record):
    findings = []
    status = record.get("status_code", 0)
    if status in [500, 502, 503]:
        findings.append(("MEDIUM", f"Server error publicly exposed (HTTP {status})"))
    if status == 403:
        findings.append(("INFO", "Access forbidden — resource exists but blocked"))
    if status == 401:
        findings.append(("INFO", "Authentication required — login panel detected"))
    return findings


def classify(record):
    host   = record.get("host", "unknown")
    status = record.get("status", record.get("status_code", ""))

    if status == "NXDOMAIN" or record.get("failed"):
        return None

    all_findings  = analyze_tls(record) + analyze_tech_stack(record) + analyze_http(record)
    info_notes    = [r for s, r in all_findings if s == "INFO"]
    risk_findings = [(s, r) for s, r in all_findings if s != "INFO"]

    risk    = "LOW"
    reasons = []

    takeover, service = is_potential_takeover(record)
    if takeover:
        risk = "CRITICAL"
        reasons.append(f"Potential subdomain takeover → {service}")

    for severity, reason in risk_findings:
        reasons.append(reason)
        if severity == "CRITICAL" and risk != "CRITICAL":
            risk = "CRITICAL"
        elif severity == "HIGH" and risk not in ["CRITICAL"]:
            risk = "HIGH"
        elif severity == "MEDIUM" and risk not in ["CRITICAL", "HIGH"]:
            risk = "MEDIUM"

    if is_direct_ip(record):
        if risk != "CRITICAL":
            risk = "HIGH"
        reasons.append("Direct IP exposure — no CDN or WAF protection")

    keyword_found, keyword = has_high_keyword(host)
    if keyword_found:
        behind_cdn = is_behind_real_cdn(record)
        if not behind_cdn and risk not in ["CRITICAL", "HIGH"]:
            risk = "HIGH"
            reasons.append(f"Sensitive keyword '{keyword}' — not behind CDN")
        elif behind_cdn and risk == "LOW":
            risk = "MEDIUM"
            reasons.append(f"Sensitive keyword '{keyword}' — behind CDN")

    has_cname       = bool(record.get("cname"))
    behind_real_cdn = is_behind_real_cdn(record)

    if risk == "LOW" and has_cname and not behind_real_cdn:
        risk = "MEDIUM"
        reasons.append("Live host with internal CNAME alias")
    if risk == "LOW" and behind_real_cdn:
        reasons.append("Live host behind CDN")
    if not reasons:
        reasons.append("No significant issues detected")

    result = {
        "host"     : host,
        "ip"       : record.get("a", record.get("ip", [])),
        "cname"    : record.get("cname", []),
        "status"   : status,
        "webserver": record.get("webserver", "unknown"),
        "risk"     : risk,
        "reasons"  : reasons,
    }

    tls = record.get("tls", {})
    if tls:
        result["tls_summary"] = {
            "version"  : tls.get("tls_version", "unknown"),
            "expired"  : tls.get("expired", False),
            "not_after": tls.get("not_after", "unknown"),
            "issuer"   : tls.get("issuer_cn", "unknown"),
        }
    if info_notes:
        result["notes"] = info_notes

    return result


class Color:
    RED     = "\033[91m"
    ORANGE  = "\033[93m"
    YELLOW  = "\033[33m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

RISK_COLORS = {"CRITICAL": Color.RED, "HIGH": Color.ORANGE, "MEDIUM": Color.YELLOW, "LOW": Color.GREEN}
RISK_ICONS  = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


def print_summary(critical, high, medium, low):
    total = len(critical) + len(high) + len(medium) + len(low)
    print(f"{Color.BOLD}{'─'*56}{Color.RESET}")
    print(f"{Color.BOLD}  ASRCE RISK REPORT — {total} hosts classified{Color.RESET}")
    print(f"{'─'*56}")
    print(f"  {Color.RED}{Color.BOLD}💀 CRITICAL : {len(critical)}{Color.RESET}")
    print(f"  {Color.ORANGE}{Color.BOLD}🔴 HIGH     : {len(high)}{Color.RESET}")
    print(f"  {Color.YELLOW}🟡 MEDIUM   : {len(medium)}{Color.RESET}")
    print(f"  {Color.GREEN}🟢 LOW      : {len(low)}{Color.RESET}")
    print(f"{'─'*56}\n")


def print_finding(result):
    risk  = result["risk"]
    color = RISK_COLORS.get(risk, Color.RESET)
    icon  = RISK_ICONS.get(risk, "•")
    tls   = result.get("tls_summary", {})

    print(f"  {color}{Color.BOLD}{icon} [{risk}] {result['host']}{Color.RESET}")
    print(f"  {Color.GRAY}{'·'*52}{Color.RESET}")
    print(f"  {Color.CYAN}  IP      :{Color.RESET} {', '.join(result.get('ip', [])) or 'unknown'}")
    print(f"  {Color.CYAN}  CNAME   :{Color.RESET} {', '.join(result.get('cname', [])) or 'none'}")
    print(f"  {Color.CYAN}  Server  :{Color.RESET} {result.get('webserver', 'unknown')}")
    print(f"  {Color.CYAN}  Status  :{Color.RESET} {result.get('status', 'unknown')}")

    if tls:
        expired_tag = f"{Color.RED} ⚠ EXPIRED{Color.RESET}" if tls.get("expired") else ""
        print(f"  {Color.CYAN}  TLS     :{Color.RESET} {tls.get('version','?').upper()} | "
              f"Expires: {str(tls.get('not_after','?'))[:10]}{expired_tag}")

    print(f"  {Color.CYAN}  Reasons :{Color.RESET}")
    for r in result["reasons"]:
        print(f"    {color}→{Color.RESET} {r}")

    for note in result.get("notes", []):
        print(f"    {Color.GRAY}ℹ {note}{Color.RESET}")
    print()


def print_section(title, findings, color):
    if not findings:
        return
    print(f"\n{color}{Color.BOLD}{'═'*56}{Color.RESET}")
    print(f"{color}{Color.BOLD}  {title} ({len(findings)}){Color.RESET}")
    print(f"{color}{Color.BOLD}{'═'*56}{Color.RESET}\n")
    for f in findings:
        print_finding(f)


def run_risk_scorer(
    input_file  = "data/dns_results.json",
    http_file   = "data/http_results.json",
    output_file = "output/report.json"
):
    try:
        with open(input_file, "r") as f:
            dns_records = json.load(f)
    except FileNotFoundError:
        dns_records = []

    try:
        with open(http_file, "r") as f:
            http_records = json.load(f)
    except FileNotFoundError:
        http_records = []

    http_map = {r.get("host", r.get("input", "")): r for r in http_records}
    for record in dns_records:
        host = record.get("host", "")
        if host in http_map:
            record.update(http_map[host])

    records = dns_records

    critical, high, medium, low = [], [], [], []
    for record in records:
        result = classify(record)
        if result is None:
            continue
        if result["risk"] == "CRITICAL":
            critical.append(result)
        elif result["risk"] == "HIGH":
            high.append(result)
        elif result["risk"] == "MEDIUM":
            medium.append(result)
        else:
            low.append(result)

    print_summary(critical, high, medium, low)
    print(f"{Color.CYAN}  Full report → output/report.json{Color.RESET}\n")

    report = {
        "meta": {
            "tool"        : "ASRCE v2.0",
            "author"      : "tales_from_terminal",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "summary": {
            "total"   : len(critical)+len(high)+len(medium)+len(low),
            "critical": len(critical),
            "high"    : len(high),
            "medium"  : len(medium),
            "low"     : len(low)
        },
        "critical": critical,
        "high"    : high,
        "medium"  : medium,
        "low"     : low,
    }

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"{Color.GREEN}[+] Report saved → {output_file}{Color.RESET}\n")