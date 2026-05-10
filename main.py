import argparse
from colorama import Fore, Style, init
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
        
    """)

def parse_args():
    parser = argparse.ArgumentParser(
        description="ASRCE - Attack Surface Recon & Classification Engine"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--silent", action="store_true", help="Minimal output")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    if not args.silent:
        banner()

    print(Fore.BLUE + f"[*] Target: {args.domain}")
    
    # Phase 1 + 2
    run_orchestrator(args.domain)
    run_normalizer()
    
    # Phase 3
    run_enricher()

    print(Fore.GREEN + "\n[+] Pipeline complete. Check output/ folder.")

    run_risk_scorer()