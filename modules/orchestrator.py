import subprocess
import threading

# ── Output storage ──
results = []
lock = threading.Lock()

def run_subfinder(domain):
    try:
        output = subprocess.check_output(
            ["subfinder", "-d", domain, "-silent"],
            stderr=subprocess.DEVNULL
        ).decode().strip().splitlines()
        output = [line for line in output if "." in line and " " not in line]  # ← add this

        with lock:
            results.extend(output)

    except Exception as e:
        print(f"[-] Subfinder error: {e}")

def run_amass(domain):
    try:
        output = subprocess.check_output(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"],
            stderr=subprocess.DEVNULL,
            timeout=60  # kill after 60 seconds
        ).decode().strip().splitlines()

        output = [line for line in output if "." in line and " " not in line]
        with lock:
            results.extend(output)

    except subprocess.TimeoutExpired:
        print("[!] Amass timed out — using subfinder results only")
    except Exception as e:
        print(f"[-] Amass error: {e}")

def run_orchestrator(domain):
    global results
    results = []  # reset every run
    print(f"[*] Starting parallel discovery for: {domain}")

    # run both tools at the same time
    t1 = threading.Thread(target=run_subfinder, args=(domain,))
    t2 = threading.Thread(target=run_amass, args=(domain,))

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    # deduplicate
    unique = list(set(results))
    print(f"[+] Discovered {len(unique)} unique subdomains")

    # save to file
    with open("data/subdomains_raw.txt", "w") as f:
        for sub in sorted(unique):
            f.write(sub + "\n")

    print("[*] Saved → data/subdomains_raw.txt")
    return unique



# TODO: add timeout to amass — currently blocks if slow
# TODO: reset results list at start of each run
# TODO: log which tool found which subdomain