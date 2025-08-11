
from datetime import datetime, timedelta, timezone
from utils.config_loader import load_config

config = load_config()

def is_in_burn_in_period(baseline_item):
    burn_in_days = config.get("detection", {}).get("burn_in_days", 3)
    first_seen = baseline_item.get("first_seen")
    if not first_seen:
        return False
    try:
        first_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        now_utc = datetime.now(timezone.utc)
        print(f"[DEBUG] Burn-in check: first_seen={first_seen}, first_dt={first_dt}, burn_in_days={burn_in_days}, now={now_utc.isoformat()}", flush=True)
        return now_utc < first_dt + timedelta(days=burn_in_days)
    except Exception as e:
        print(f"[ERROR] Burn-in comparison failed: {e}", flush=True)
        return False

