import re

def is_valid_domain(domain):
    # regex checks it looks like a real domain
    pattern = r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$"
    return re.match(pattern, domain)

def detect_wildcard(subdomains):
    # if many subdomains share same IP its a wildcard — noise
    # for now flag it as a warning, full IP check comes in enricher
    seen = {}
    for sub in subdomains:
        base = ".".join(sub.split(".")[-2:])
        seen[base] = seen.get(base, 0) + 1
    
    for base, count in seen.items():
        if count > 50:
            print(f"[!] Possible wildcard DNS detected for {base} — {count} subdomains")

def run_normalizer(input_file="data/subdomains_raw.txt", 
                   output_file="data/subdomains_clean.txt"):
    
    print("[*] Starting normalization...")

    try:
        with open(input_file, "r") as f:
            raw = f.read().splitlines()
    except FileNotFoundError:
        print("[-] No input file found. Run orchestrator first.")
        return []

    # deduplicate
    unique = list(set(raw))
    
    # validate each domain
    valid = [d.strip().lower() for d in unique if is_valid_domain(d.strip())]
    
    # wildcard check
    detect_wildcard(valid)

    # save
    with open(output_file, "w") as f:
        for sub in sorted(valid):
            f.write(sub + "\n")

    print(f"[+] {len(raw)} raw → {len(valid)} clean subdomains")
    print(f"[*] Saved → {output_file}")
    
    return valid