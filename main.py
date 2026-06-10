import re
import argparse
import sys
import os
import json
import logging
from datetime import datetime
from pathlib import Path
from colorama import Fore, init

from modules.orchestrator import run_orchestrator
from modules.normalizer import run_normalizer
from modules.enricher import run_enricher
from modules.risk_scorer import run_risk_scorer
from modules.state_manager import save_state, load_state, get_state_path

init(autoreset=True)

def banner():
    print(Fore.CYAN + r"""
    █████╗ ███████╗██████╗  ██████╗███████╗
   ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
   ███████║███████╗██████╔╝██║     █████╗  
   ██╔══██║╚════██║██╔══██╗██║     ██╔══╝  
   ██║  ██║███████║██║  ██║╚██████╗███████╗
   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚══════╝
        Attack Surface Recon & Classification Engine
    """)

def setup_logging(domain):
    log_dir = Path("data/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"{domain}_{timestamp}.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
    )
    return str(log_file)

def is_valid_domain(domain):
    if not domain or len(domain) > 253:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1].lower()
    if len(tld) < 2 or not tld.isalpha():
        return False
    blocked = {"localhost", "local", "internal", "corp", "home", "lan", "test"}
    if tld in blocked:
        return False
    for label in labels[:-1]:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.match(r"^[A-Za-z0-9-]+$", label):
            return False
        if "--" in label and not label.startswith("xn--"):
            return False
    return True

def parse_args():
    parser = argparse.ArgumentParser(description="ASRCE - Attack Surface Recon & Classification Engine")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("--silent", action="store_true", help="Minimal output")
    parser.add_argument("--report-only", action="store_true", help="Classify existing data only")
    parser.add_argument("--resume", action="store_true", help="Resume interrupted scan")
    parser.add_argument("--threads", type=int, default=50, help="Max threads (default: 50)")
    parser.add_argument("--rate-limit", "-rl", type=int, default=0, help="Rate limit per second")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds")
    parser.add_argument("--resolvers", help="Comma-separated DNS resolvers")
    return parser.parse_args()

def main():
    args = parse_args()
    logger = logging.getLogger("asrce.main")

    if not args.silent:
        banner()

    # ─── REPORT-ONLY MODE ───
    if args.report_only:
        print(Fore.BLUE + "[*] Report-only mode")
        logger.info("Starting report-only mode")
        
        last_data = Path("data/last_enrichment.json")
        if not last_data.exists():
            print(Fore.RED + "[-] No existing data found. Run a full scan first.")
            sys.exit(1)
        
        with open(last_data) as f:
            enriched = json.load(f)
        
        # Extract domain from last enrichment data or use a default
        domain = enriched[0].get("host", "unknown") if enriched else "unknown"
        report_json = f"output/report_{domain}.json"
        report_html = f"output/report_{domain}.html"
        
        run_risk_scorer(
            enriched_data=enriched,
            output_json=report_json,
            output_html=report_html,
            domain=domain
        )
        print(Fore.GREEN + "[+] Report-only complete.")
        print(Fore.GREEN + f"    JSON → {report_json}")
        print(Fore.GREEN + f"    HTML → {report_html}")
        sys.exit(0)

    # ─── FULL SCAN MODE ───
    if not args.domain:
        print(Fore.RED + "[-] Provide a domain with -d or use --report-only")
        sys.exit(1)

    domain = args.domain.lower().strip()
    if not is_valid_domain(domain):
        print(Fore.RED + f"[-] Invalid domain: {domain}")
        sys.exit(1)

    Path("output").mkdir(parents=True, exist_ok=True)
    Path("data").mkdir(parents=True, exist_ok=True)
    log_file = setup_logging(domain)
    logger.info(f"Target: {domain}")

    config = {
        "domain": domain,
        "threads": args.threads,
        "rate_limit": args.rate_limit,
        "timeout": args.timeout,
        "resolvers": args.resolvers.split(",") if args.resolvers else None,
        "silent": args.silent,
        "go_bin": os.environ.get("GO_BIN", os.path.expanduser("~/go/bin"))
    }

    try:
        # Stage 1: Discovery
        print(Fore.BLUE + f"[*] Target: {domain}")
        print(Fore.YELLOW + "[1/4] Orchestration — subdomain discovery")
        subdomains = run_orchestrator(config)

        if not subdomains:
            print(Fore.RED + "[!] No subdomains found.")
            save_state(domain, "orchestration", {})
            sys.exit(2)

        save_state(domain, "orchestration", subdomains)

        # Stage 2: Normalize
        print(Fore.YELLOW + "[2/4] Normalization — deduplication & validation")
        subdomains = run_normalizer(subdomains, config)

        if not subdomains:
            print(Fore.RED + "[!] All subdomains filtered out.")
            save_state(domain, "normalization", {})
            sys.exit(2)

        save_state(domain, "normalization", subdomains)

        # Stage 3: Enrich
        print(Fore.YELLOW + "[3/4] Enrichment — DNS + HTTP + WAF")
        enriched = run_enricher(subdomains, config)

        with open("data/last_enrichment.json", "w") as f:
            json.dump(enriched, f, indent=2)

        save_state(domain, "enrichment", enriched)

        # Stage 4: Score
        print(Fore.YELLOW + "[4/4] Risk Scoring — classification & reports")
        report_json = f"output/report_{domain}.json"
        report_html = f"output/report_{domain}.html"

        run_risk_scorer(
            enriched_data=enriched,
            output_json=report_json,
            output_html=report_html,
            domain=domain  # <-- FIXED: passes correct domain
        )

        # Cleanup state on success
        state_path = get_state_path(domain)
        if state_path.exists():
            state_path.unlink()

        print(Fore.GREEN + f"\n[+] Pipeline complete.")
        print(Fore.GREEN + f"    JSON → {report_json}")
        print(Fore.GREEN + f"    HTML → {report_html}")
        print(Fore.GREEN + f"    Log  → {log_file}")

    except KeyboardInterrupt:
        print(Fore.RED + f"\n[!] Interrupted. Resume with: python3 main.py -d {domain} --resume")
        sys.exit(130)
    except Exception as e:
        logger.exception("Pipeline crashed")
        print(Fore.RED + f"\n[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()