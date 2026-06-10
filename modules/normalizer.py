import re
import logging
from collections import defaultdict

logger = logging.getLogger("asrce.normalizer")

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

def detect_wildcard(subdomains):
    base_counts = defaultdict(int)
    for sub in subdomains:
        parts = sub.split(".")
        if len(parts) >= 3:
            base = ".".join(parts[-3:])
        else:
            base = ".".join(parts[-2:])
        base_counts[base] += 1

    warnings = []
    for base, count in base_counts.items():
        if count > 50:
            msg = f"Possible wildcard DNS for {base} — {count} subdomains"
            warnings.append(msg)
            logger.warning(msg)
    return warnings

def run_normalizer(subdomains_dict, config):
    logger.info("Starting normalization...")

    if not subdomains_dict:
        logger.warning("No subdomains to normalize")
        return {}

    valid = {}
    for domain, meta in subdomains_dict.items():
        if is_valid_domain(domain):
            valid[domain] = meta
        else:
            logger.debug(f"Filtered invalid domain: {domain}")

    detect_wildcard(list(valid.keys()))

    logger.info(f"Normalization: {len(subdomains_dict)} raw → {len(valid)} clean")
    return valid