from datetime import datetime
from decimal import Decimal

def _trusted_hours_from_ns(baseline_item):
    out = set()
    ns = baseline_item.get("work_hours_utc_ns")
    if not ns:
        return out

    if isinstance(ns, set):
        for h in ns:
            out.add(int(h) if not isinstance(h, Decimal) else int(h))
    elif isinstance(ns, list):
        for h in ns:
            out.add(int(h) if not isinstance(h, Decimal) else int(h))
    return out


def detect_user_behavior_anomaly(record, baseline, write_alert, username):
    event_name  = record.get("eventName", "unknown")
    timestamp   = record.get("eventTime", "")
    source_ip   = record.get("sourceIPAddress", "unknown")
    user_agent  = record.get("userAgent", "unknown")
    region      = record.get("awsRegion", "unknown")
    service     = record.get("eventSource", "unknown")

    anomalies = []
    candidates = baseline.get("candidates", {}) or {}

    def is_candidate(field, value):
        return value in (candidates.get(field, {}) or {})

    event_hour = None
    hour_key = None
    try:
        event_hour = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
        hour_key = str(event_hour).zfill(2)
    except Exception as e:
        print(f"[WARN] Failed to parse hour from timestamp: {e}", flush=True)

    if source_ip and source_ip not in (baseline.get("known_ips", []) or []) and not is_candidate("known_ips", source_ip):
        anomalies.append(("sourceIPAddress", source_ip))

    if user_agent and user_agent not in (baseline.get("user_agents", []) or []) and not is_candidate("user_agents", user_agent):
        anomalies.append(("userAgent", user_agent))

    if region and region not in (baseline.get("regions", []) or []) and not is_candidate("regions", region):
        anomalies.append(("awsRegion", region))

    if service and service not in (baseline.get("services", []) or []) and not is_candidate("services", service):
        anomalies.append(("eventSource", service))

    if event_hour is not None:
        trusted_hours = _trusted_hours_from_ns(baseline)
        if trusted_hours:
            hour_is_candidate = hour_key in (candidates.get("work_hours_utc", {}) or {})
            if (event_hour not in trusted_hours) and not hour_is_candidate:
                anomalies.append(("work_hours_utc", hour_key))

    if anomalies:
        print(f"[ALERT] User behavior anomaly detected for {username}: {anomalies}", flush=True)
        write_alert(
            alert_type="User Behavior Anomaly",
            metadata={
                "severity": "medium",
                "category": "behavior",
                "actor_type": "human",
                "timestamp": timestamp
            },
            details={
                "user": username,
                "event": event_name,
                "unseen_fields": anomalies,
                "event_hour": event_hour,
                "region": region,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "service": service
            }
        )

