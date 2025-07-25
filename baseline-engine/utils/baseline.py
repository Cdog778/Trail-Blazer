import re
import time
from datetime import datetime

def normalize_user(identity):
    return identity.get("userName") or identity.get("principalId") or "unknown"

def _now_ts():
    return int(time.time())

def _days_to_seconds(days):
    return days * 24 * 3600

def record_candidate(username, field_key, value, table, thresholds):
    now_ts = _now_ts()
    now_hr = datetime.utcfromtimestamp(now_ts).isoformat() + "Z"
    ttl    = now_ts + _days_to_seconds(thresholds["max_age_days"] * 2)

    try:
        # Step 1: Ensure `candidates` exists
        table.update_item(
            Key={"username": username},
            UpdateExpression="SET candidates = if_not_exists(candidates, :empty_map)",
            ExpressionAttributeValues={":empty_map": {}}
        )

        # Step 2: Ensure `candidates.#f` (e.g. "sourceIPAddress") exists
        table.update_item(
            Key={"username": username},
            UpdateExpression="SET candidates.#f = if_not_exists(candidates.#f, :empty_map)",
            ExpressionAttributeNames={
                "#f": field_key
            },
            ExpressionAttributeValues={
                ":empty_map": {}
            }
        )

        # Step 3: Ensure `candidates.#f.#v` (e.g. "sourceIPAddress.192.168.1.1") exists
        table.update_item(
            Key={"username": username},
            UpdateExpression="SET candidates.#f.#v = if_not_exists(candidates.#f.#v, :empty_map)",
            ExpressionAttributeNames={
                "#f": field_key,
                "#v": value
            },
            ExpressionAttributeValues={
                ":empty_map": {}
            }
        )

    except Exception as e:
        print(f"[ERROR] Failed to initialize candidate path: {e}", flush=True)
        return

    try:
        # Step 4: Update all attributes inside the map
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
        print(f"[ERROR] Failed to update candidate metrics: {e}", flush=True)

def should_promote_candidate(item, field_key, value, thresholds):
    # Don't promote if value is already in the trusted set
    if value in item.get(field_key, []):
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

    # Remove the candidate entry
    table.update_item(
        Key={"username": username},
        UpdateExpression="REMOVE candidates.#f.#v",
        ExpressionAttributeNames={"#f": field_key, "#v": value}
    )

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

