import re
import time
from datetime import datetime
from decimal import Decimal  

def normalize_user(identity):
    if not identity:
        return "unknown"

    if identity.get("userName"):
        return identity["userName"]

    if identity.get("type") == "AssumedRole":
        session_issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
        name = session_issuer.get("userName") or session_issuer.get("arn")
        if name and ":" not in name:
            return name

    arn = identity.get("arn") or identity.get("principalId", "unknown")
    return re.split(r"[:/]+", arn)[-1] if arn else "unknown"

def _now_ts():
    return int(time.time())

def _days_to_seconds(days):
    return days * 24 * 3600

def _trusted_hours_set(item: dict) -> set[int]:
    out = set()
    ns = item.get("work_hours_utc_ns")
    if not ns:
        return out

    if isinstance(ns, dict) and "NS" in ns:
        it = ns["NS"]
    elif isinstance(ns, set):
        it = ns
    elif isinstance(ns, list):
        it = ns
    else:
        it = []

    for h in it:
        try:
            out.add(int(h) if not isinstance(h, Decimal) else int(h))
        except Exception:
            pass
    return out

def is_trusted(item: dict, field_key: str, value: str) -> bool:
    if field_key == "work_hours_utc":
        try:
            return int(value) in _trusted_hours_set(item)
        except Exception:
            return False
    return value in (item.get(field_key) or [])

def clear_candidate(username: str, field_key: str, value: str, table):
    try:
        table.update_item(
            Key={"username": username},
            UpdateExpression="REMOVE candidates.#f.#v",
            ExpressionAttributeNames={"#f": field_key, "#v": value}
        )
    except Exception:
        pass

def record_candidate(username, field_key, value, table, thresholds):
    now_ts = _now_ts()
    now_hr = datetime.utcfromtimestamp(now_ts).isoformat() + "Z"
    ttl    = now_ts + _days_to_seconds(thresholds["max_age_days"] * 2)

    item = table.get_item(Key={"username": username}).get("Item", {})
    if is_trusted(item, field_key, value):
        return

    try:
        table.update_item(
            Key={"username": username},
            UpdateExpression="SET candidates = if_not_exists(candidates, :empty_map)",
            ExpressionAttributeValues={":empty_map": {}}
        )

        table.update_item(
            Key={"username": username},
            UpdateExpression="SET candidates.#f = if_not_exists(candidates.#f, :empty_map)",
            ExpressionAttributeNames={"#f": field_key},
            ExpressionAttributeValues={":empty_map": {}}
        )

        table.update_item(
            Key={"username": username},
            UpdateExpression="SET candidates.#f.#v = if_not_exists(candidates.#f.#v, :empty_map)",
            ExpressionAttributeNames={"#f": field_key, "#v": value},
            ExpressionAttributeValues={":empty_map": {}}
        )

        update_expr = (
            "SET candidates.#f.#v.#last_seen = :now_ts, "
            "candidates.#f.#v.#ttl = :ttl, "
            "candidates.#f.#v.#first_seen = if_not_exists(candidates.#f.#v.#first_seen, :now_ts), "
            "candidates.#f.#v.#first_seen_hr = if_not_exists(candidates.#f.#v.#first_seen_hr, :now_hr) "
            "ADD candidates.#f.#v.#count :inc"
        )

        table.update_item(
            Key={"username": username},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={
                "#f": field_key,
                "#v": value,
                "#ttl": "ttl",
                "#count": "count",
                "#first_seen": "first_seen",
                "#first_seen_hr": "first_seen_hr",
                "#last_seen": "last_seen"
            },
            ExpressionAttributeValues={
                ":now_ts": now_ts,
                ":now_hr": now_hr,
                ":ttl": ttl,
                ":inc": 1
            }
        )

    except Exception as e:
        print(f"[ERROR] Failed to record candidate {field_key}={value} for {username}: {e}", flush=True)

def should_promote_candidate(item, field_key, value, thresholds):
    # Already trusted? don't promote again
    if is_trusted(item, field_key, value):
        return False

    c = item.get("candidates", {}).get(field_key, {}).get(value)
    if not c:
        return False

    count = c.get("count", 0)
    age   = _now_ts() - c.get("first_seen", 0)
    return count >= thresholds["min_count"] and age <= _days_to_seconds(thresholds["max_age_days"])

def promote_candidate(username, field_key, value, table):
    resp = table.get_item(Key={"username": username})
    item = resp.get("Item", {})
    current_ss = item.get(field_key, [])

    if value not in current_ss:
        new_ss = current_ss + [value]
        table.update_item(
            Key={"username": username},
            UpdateExpression="SET #f = :new_ss",
            ExpressionAttributeNames={"#f": field_key},
            ExpressionAttributeValues={":new_ss": new_ss}
        )

    clear_candidate(username, field_key, value, table)

    print(f"[INFO] Promoted value '{value}' for user '{username}' under field '{field_key}'", flush=True)

def alert_promotion(username, field_key, value, write_alert):
    write_alert(
        alert_type="Baseline Promotion",
        metadata={
            "severity": "info",
            "category": "baseline",
            "actor_type": "system",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        },
        details={
            "user": username,
            "field": field_key,
            "value": value
        }
    )

