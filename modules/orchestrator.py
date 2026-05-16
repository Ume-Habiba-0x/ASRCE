import subprocess
import threading
import re

# ── Output storage ──
results = []
lock = threading.Lock()

def run_subfinder(domain):
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout.strip().splitlines()
        # clean markdown links and filter valid domains
        cleaned = []
        for line in output:
            line = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', line).strip()
            if "." in line and " " not in line and line:
                cleaned.append(line)
        output = cleaned
        with lock:
            results.extend(output)
        print(f"[*] Subfinder found: {len(output)} subdomains")
    except Exception as e:
        print(f"[-] Subfinder error: {e}")

def run_amass(domain):
    try:
        output = subprocess.check_output(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"],
            stderr=subprocess.DEVNULL,
            timeout=60
        ).decode().strip().splitlines()
        cleaned = []
        for line in output:
            line = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', line).strip()
            if "." in line and " " not in line and line:
                cleaned.append(line)
        output = cleaned
        with lock:
            results.extend(output)
    except subprocess.TimeoutExpired:
        print("[!] Amass timed out — using subfinder results only")
    except Exception as e:
        print(f"[-] Amass error: {e}")

def run_orchestrator(domain):
    global results
    results = []
    print(f"[*] Starting parallel discovery for: {domain}")
    t1 = threading.Thread(target=run_subfinder, args=(domain,))
    t2 = threading.Thread(target=run_amass, args=(domain,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    unique = list(set(results))
    print(f"[+] Discovered {len(unique)} unique subdomains")
    with open("data/subdomains_raw.txt", "w") as f:
        for sub in sorted(unique):
            f.write(sub + "\n")
    print("[*] Saved → data/subdomains_raw.txt")
    return unique
# TODO: add timeout to amass — currently blocks if slow
# TODO: log which tool found which subdomain