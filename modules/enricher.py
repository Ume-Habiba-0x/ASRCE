import subprocess
import json
import logging
import os
import random
import concurrent.futures
from pathlib import Path
from shutil import which

logger = logging.getLogger("asrce.enricher")

def get_tool_path(name, go_bin=""):
    if go_bin:
        path = os.path.join(go_bin, name)
        if os.path.exists(path):
            return path
    return name

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101"
]

def run_dnsx(subdomains_dict, config):
    go_bin = config.get("go_bin", "")
    threads = min(config.get("threads", 50), 50)
    resolvers = config.get("resolvers") or [
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "1.0.0.1"
    ]

    input_file = Path("data/subdomains_clean.txt")
    input_file.parent.mkdir(parents=True, exist_ok=True)
    with open(input_file, "w") as f:
        for sub in subdomains_dict.keys():
            f.write(sub + "\n")

    cmd = [
        get_tool_path("dnsx", go_bin),
        "-l", str(input_file),
        "-json", "-silent",
        "-a", "-cname", "-resp",
        "-t", str(threads),
    ]

    if resolvers:
        resolver_file = Path("data/resolvers.txt")
        with open(resolver_file, "w") as f:
            for r in resolvers:
                f.write(r + "\n")
        cmd.extend(["-r", str(resolver_file)])

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode != 0:
            logger.error(f"dnsx exited {result.returncode}: {result.stderr}")
            return []

        records = []
        for line in result.stdout.strip().splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if not records:
            logger.warning(f"dnsx returned 0 records. stdout sample: {result.stdout[:200]}")

        logger.info(f"DNS enrichment complete — {len(records)} records")
        return records
    except Exception as e:
        logger.error(f"dnsx error: {e}")
        return []

def run_httpx(alive_hosts, config):
    go_bin = config.get("go_bin", "")
    threads = min(config.get("threads", 50), 50)
    rate_limit = config.get("rate_limit", 0)
    timeout = config.get("timeout", 30)

    input_file = Path("data/httpx_input.txt")
    input_file.parent.mkdir(parents=True, exist_ok=True)
    with open(input_file, "w") as f:
        for host in alive_hosts:
            f.write(host + "\n")

    cmd = [
        get_tool_path("httpx", go_bin),
        "-l", str(input_file),
        "-json", "-silent",
        "-status-code", "-title", "-tech-detect",
        "-cdn", "-tls-grab",
        "-t", str(threads),
        "-timeout", str(timeout)
    ]
    if rate_limit > 0:
        cmd.extend(["-rl", str(rate_limit)])

    ua = random.choice(USER_AGENTS)
    cmd.extend(["-H", f"User-Agent: {ua}"])

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode not in [0, 1]:
            logger.error(f"httpx exited {result.returncode}: {result.stderr}")
            return []

        records = []
        for line in result.stdout.strip().splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        logger.info(f"HTTP enrichment complete — {len(records)} live hosts")
        return records
    except Exception as e:
        logger.error(f"httpx error: {e}")
        return []

def _check_single_waf(host, waf_bin):
    try:
        result = subprocess.run(
            [waf_bin, "-a", "-o", "-", f"http://{host}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return host, None

        output = result.stdout
        if "No WAF" in output:
            return host, None

        for line in output.splitlines():
            if "behind" in line.lower() and "WAF" in line:
                parts = line.split()
                if len(parts) >= 3:
                    return host, " ".join(parts[2:]).strip()
        return host, "Unknown WAF"
    except Exception:
        return host, None

def run_wafw00f(hosts, config):
    waf_bin = os.environ.get("WAFW00F_BIN", "wafw00f")

    if not which(waf_bin):
        logger.warning(f"wafw00f not found ({waf_bin}). Skipping WAF detection.")
        return {h: None for h in hosts}

    logger.info(f"Running wafw00f on {len(hosts)} hosts (5 workers, 10s timeout)...")

    waf_results = {}
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_host = {
            executor.submit(_check_single_waf, host, waf_bin): host
            for host in hosts
        }

        for future in concurrent.futures.as_completed(future_to_host):
            host, waf = future.result()
            waf_results[host] = waf
            completed += 1
            if completed % 10 == 0 or completed == len(hosts):
                logger.info(f"WAF progress: {completed}/{len(hosts)}")

    detected = sum(1 for v in waf_results.values() if v)
    logger.info(f"WAF detection complete — {detected} hosts behind WAF")
    return waf_results

def run_enricher(subdomains_dict, config):
    dns_records = run_dnsx(subdomains_dict, config)

    alive_hosts = []
    dns_host_map = {}
    for record in dns_records:
        host = record.get("host", "")
        if host and record.get("a"):
            alive_hosts.append(host)
            dns_host_map[host] = record

    if not alive_hosts:
        logger.warning("No alive hosts found via DNS")
        return []

    logger.info(f"Filtering {len(alive_hosts)} alive hosts for HTTP probing")

    http_records = run_httpx(alive_hosts, config)

    waf_results = run_wafw00f(alive_hosts, config)

    enriched = {}
    for record in http_records:
        host = record.get("host", record.get("input", ""))
        if not host:
            continue

        merged = dict(dns_host_map.get(host, {}))
        merged.update(record)
        merged["waf"] = waf_results.get(host)

        if host in subdomains_dict:
            merged["sources"] = subdomains_dict[host].get("sources", [])
            merged["confidence"] = subdomains_dict[host].get("confidence", 1)

        enriched[host] = merged

    for host in alive_hosts:
        if host not in enriched:
            merged = dict(dns_host_map[host])
            merged["waf"] = waf_results.get(host)
            merged["sources"] = subdomains_dict[host].get("sources", [])
            merged["confidence"] = subdomains_dict[host].get("confidence", 1)
            enriched[host] = merged

    result_list = list(enriched.values())

    with open("data/last_enrichment.json", "w") as f:
        json.dump(result_list, f, indent=2)

    return result_list