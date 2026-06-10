import json
from pathlib import Path
from datetime import datetime

STATE_DIR = Path("data/state")

def get_state_path(domain):
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    return STATE_DIR / f"{safe_domain}_state.json"

def save_state(domain, completed_stage, data):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = {
        "domain": domain,
        "completed_stage": completed_stage,
        "timestamp": datetime.now().isoformat(),
        "data": data
    }
    with open(get_state_path(domain), "w") as f:
        json.dump(state, f, indent=2)

def load_state(domain):
    path = get_state_path(domain)
    if not path.exists():
        return None
    with open(path, "r") as f:
        return json.load(f)