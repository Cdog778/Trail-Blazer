from datetime import datetime, timedelta
from utils.config_loader import load_config

config = load_config()

def is_in_burn_in_period(baseline_item):
    burn_in_days = config.get("detection", {}).get("burn_in_days", 3)
    first_seen = baseline_item.get("first_seen")
    if not first_seen:
        return False
    try:
        first_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        print(f"[DEBUG] Burn-in check: first_seen={first_seen}, first_dt={first_dt}, burn_in_days={burn_in_days}, now={datetime.utcnow().isoformat()}Z", flush=True)
    return datetime.utcnow() < first_dt + timedelta(days=burn_in_days)
    except Exception:
        return False


