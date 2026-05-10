import subprocess
import json

def run_dnsx(input_file="data/subdomains_clean.txt",
             output_file="data/dns_results.json"):

    print("[*] Running DNS enrichment via dnsx...")

    try:
        result = subprocess.check_output(
            ["dnsx", "-l", input_file, "-json", "-silent",
             "-a", "-cname", "-resp"],
            stderr=subprocess.DEVNULL
        ).decode().strip()

        records = []
        for line in result.splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        with open(output_file, "w") as f:
            json.dump(records, f, indent=2)

        print(f"[+] DNS enrichment complete — {len(records)} records")
        return records

    except Exception as e:
        print(f"[-] dnsx error: {e}")
        return []


def run_httpx(input_file="data/subdomains_clean.txt",
              output_file="data/http_results.json"):

    print("[*] Running HTTP enrichment via httpx...")

    try:
        result = subprocess.check_output(
            ["httpx", "-l", input_file, "-json", "-silent",
             "-status-code", "-title", "-tech-detect",
             "-cdn", "-tls-grab"],
            stderr=subprocess.DEVNULL
        ).decode().strip()

        records = []
        for line in result.splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        with open(output_file, "w") as f:
            json.dump(records, f, indent=2)

        print(f"[+] HTTP enrichment complete — {len(records)} live hosts")
        return records

    except Exception as e:
        print(f"[-] httpx error: {e}")
        return []


def run_enricher():
    dns_data = run_dnsx()
    http_data = run_httpx()
    return dns_data, http_data