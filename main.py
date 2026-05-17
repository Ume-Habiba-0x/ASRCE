import argparse
from colorama import Fore, init
from modules.orchestrator import run_orchestrator
from modules.normalizer import run_normalizer
from modules.enricher import run_enricher
from modules.risk_scorer import run_risk_scorer

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
        tales_from_terminal
    """)

def parse_args():
    parser = argparse.ArgumentParser(
        description="ASRCE - Attack Surface Recon & Classification Engine"
    )
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("--silent", action="store_true", help="Minimal output")
    parser.add_argument("--report-only", action="store_true", help="Classify existing data only")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    if not args.silent:
        banner()

    if args.report_only:
        print(Fore.BLUE + "[*] Report-only mode — classifying existing data")
        run_risk_scorer(output_file="output/report_last.json")
    else:
        if not args.domain:
            print(Fore.RED + "[-] Provide a domain with -d or use --report-only")
            exit(1)

        print(Fore.BLUE + f"[*] Target: {args.domain}")

        run_orchestrator(args.domain)
        run_normalizer()
        run_enricher()
        run_risk_scorer(output_file=f"output/report_{args.domain}.json")

        print(Fore.GREEN + f"\n[+] Pipeline complete. Report saved → output/report_{args.domain}.json")