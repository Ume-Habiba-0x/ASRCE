import subprocess
import concurrent.futures
import threading
import re
import os
import logging
import time

logger = logging.getLogger("asrce.orchestrator")

class RateLimiter:
    def __init__(self, max_per_second=0):
        self.min_interval = 1.0 / max_per_second if max_per_second > 0 else 0
        self.last_time = 0
        self.lock = threading.Lock()

    def acquire(self):
        if self.min_interval <= 0:
            return
        with self.lock:
            now = time.time()
            elapsed = now - self.last_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_time = time.time()

def get_tool_path(name, go_bin=""):
    if go_bin:
        path = os.path.join(go_bin, name)
        if os.path.exists(path):
            return path
    return name

def run_subfinder(domain, config):
    limiter = RateLimiter(config.get("rate_limit", 0))
    go_bin = config.get("go_bin", "")
    resolvers = config.get("resolvers") or [
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "1.0.0.1"
    ]

    cmd = [
        get_tool_path("subfinder", go_bin),
        "-d", domain,
        "-silent",
        "-r", ",".join(resolvers)
    ]

    limiter.acquire()
    logger.info(f"Running subfinder for {domain}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            logger.error(f"subfinder exited {result.returncode}: {result.stderr}")
            return {}

        found = {}
        for line in result.stdout.strip().splitlines():
            line = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', line).strip()
            if "." in line and " " not in line and line:
                found[line.lower()] = {"sources": ["subfinder"], "confidence": 1}
        logger.info(f"Subfinder found {len(found)} subdomains")
        return found
    except Exception as e:
        logger.error(f"Subfinder error: {e}")
        return {}

def run_amass(domain, config):
    limiter = RateLimiter(config.get("rate_limit", 0))
    go_bin = config.get("go_bin", "")

    cmd = [
        get_tool_path("amass", go_bin),
        "enum", "-passive", "-d", domain, "-timeout", "1"
    ]

    limiter.acquire()
    logger.info(f"Running amass for {domain}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            logger.error(f"amass exited {result.returncode}: {result.stderr}")
            return {}

        found = {}
        for line in result.stdout.strip().splitlines():
            line = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', line).strip()
            if "." in line and " " not in line and line:
                found[line.lower()] = {"sources": ["amass"], "confidence": 1}
        logger.info(f"Amass found {len(found)} subdomains")
        return found
    except subprocess.TimeoutExpired:
        logger.warning("Amass timed out — continuing with subfinder data")
        return {}
    except Exception as e:
        logger.error(f"Amass error: {e}")
        return {}

def run_orchestrator(config):
    domain = config["domain"]
    logger.info(f"Starting parallel discovery for: {domain}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_sub = executor.submit(run_subfinder, domain, config)
        future_amass = executor.submit(run_amass, domain, config)

        sub_results = future_sub.result()
        amass_results = future_amass.result()

    merged = dict(sub_results)
    for host, data in amass_results.items():
        if host in merged:
            sources = list(set(merged[host]["sources"] + data["sources"]))
            merged[host]["sources"] = sources
            merged[host]["confidence"] = len(sources)
        else:
            merged[host] = data

    logger.info(f"Discovered {len(merged)} unique subdomains (confidence tracked)")
    return merged