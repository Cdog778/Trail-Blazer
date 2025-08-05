from datetime import datetime
from utils.config_loader import load_config

def detect_user_behavior_anomaly(record, baseline, write_alert):
    username    = record.get("userIdentity", {}).get("userName", "unknown")
    event_name  = record.get("eventName", "unknown")
    timestamp   = record.get("eventTime", "")
    source_ip   = record.get("sourceIPAddress", "unknown")
    user_agent  = record.get("userAgent", "unknown")
    region      = record.get("awsRegion", "unknown")
    service     = record.get("eventSource", "unknown")

    anomalies = []
    candidates = baseline.get("candidates", {})

    def is_candidate(field, value):
        return value in candidates.get(field, {})

    config = load_config()
    event_hour = None
    try:
        event_hour = str(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour).zfill(2)
    except Exception as e:
        print(f"[WARN] Failed to parse hour from timestamp: {e}", flush=True)

    allowed_hours = config.get("users", {}).get(username, {}).get("allowed_hours_utc") or \
                    config.get("defaults", {}).get("allowed_hours_by_region", {}).get(region) or \
                    baseline.get("work_hours_utc", [])

    if source_ip and source_ip not in baseline.get("known_ips", []) and not is_candidate("known_ips", source_ip):
        anomalies.append(("sourceIPAddress", source_ip))

    if user_agent and user_agent not in baseline.get("user_agents", []) and not is_candidate("user_agents", user_agent):
        anomalies.append(("userAgent", user_agent))

    if region and region not in baseline.get("regions", []) and not is_candidate("regions", region):
        anomalies.append(("awsRegion", region))

    if service and service not in baseline.get("services", []) and not is_candidate("services", service):
        anomalies.append(("eventSource", service))

    if event_hour and allowed_hours and event_hour not in allowed_hours:
        anomalies.append(("work_hours_utc", event_hour))

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

