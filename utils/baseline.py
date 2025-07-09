import time
from datetime import datetime, timedelta

def normalize_user(identity):
    return identity.get("userName") or identity.get("principalId") or "unknown"

def _now_ts():
    return int(time.time())

def _days_to_seconds(days):
    return days * 24 * 3600

def record_candidate(username, field_key, value, table, thresholds):
    now_ts = int(time.time())
    now_hr = datetime.utcfromtimestamp(now_ts).isoformat() + "Z"
    ttl = now_ts + (thresholds["max_age_days"] * 2 * 24 * 3600)  # Extra buffer

    candidate_path = f"candidates.{field_key}.{value}"

    table.update_item(
        Key={"username": username},
        UpdateExpression=(
            f"SET {candidate_path}.last_seen = :now_ts, "
            f"{candidate_path}.ttl = :ttl, "
            f"{candidate_path}.first_seen = if_not_exists({candidate_path}.first_seen, :now_ts), "
            f"{candidate_path}.first_seen_hr = if_not_exists({candidate_path}.first_seen_hr, :now_hr), "
            f"{candidate_path}.count = if_not_exists({candidate_path}.count, :zero) + :inc"
        ),
        ExpressionAttributeValues={
            ":now_ts": now_ts,
            ":now_hr": now_hr,
            ":ttl": ttl,
            ":inc": 1,
            ":zero": 0
        }
    )


def should_promote_candidate(item, field_key, value, thresholds):
    """
    Check whether this candidate meets promotion thresholds.
    """
    c = item.get("candidates", {}).get(field_key, {}).get(value)
    if not c:
        return False

    count = c.get("count", 0)
    first_seen = c.get("first_seen", 0)
    age = _now_ts() - first_seen

    return (count >= thresholds["min_count"]
            and age <= _days_to_seconds(thresholds["max_age_days"]))

def promote_candidate(username, field_key, value, table):
    """
    Move from candidates → confirmed baseline, remove from candidates.
    """
    # Add to confirmed list
    table.update_item(
        Key={"username": username},
        UpdateExpression=(
            f"ADD {field_key} :val_set "
            f"REMOVE candidates.{field_key}.{value}"
        ),
        ExpressionAttributeValues={":val_set": { "SS": [value] }}
    )

def alert_promotion(username, field_key, value, write_alert):
    """
    Fire an alert whenever we promote a candidate.
    """
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

