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

    # Load config once
    config = load_config()

    # Extract event hour in UTC
    event_hour = None
    try:
        event_hour = str(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour).zfill(2)
    except Exception as e:
        print(f"[WARN] Failed to parse hour from timestamp: {e}", flush=True)

    allowed_hours = config.get("users", {}).get(username, {}).get("allowed_hours_utc")

    if not allowed_hours:
        allowed_hours = config.get("defaults", {}).get("allowed_hours_by_region", {}).get(region)

    if allowed_hours and event_hour:
        if event_hour not in allowed_hours:
            print(f"[ALERT] Off-hours activity for {username}: {event_hour} not in {allowed_hours}", flush=True)
            write_alert(
                alert_type="Off-Hours Activity",
                metadata={
                    "severity": "medium",
                    "category": "behavior",
                    "actor_type": "human",
                    "timestamp": timestamp
                },
                details={
                    "user": username,
                    "event": event_name,
                    "event_hour": event_hour,
                    "allowed_hours": allowed_hours,
                    "region": region,
                    "source_ip": source_ip,
                    "user_agent": user_agent,
                    "service": service
                }
            )
            return  


    if source_ip and source_ip not in baseline.get("known_ips", []):
        anomalies.append(("sourceIPAddress", source_ip))

    if user_agent and user_agent not in baseline.get("user_agents", []):
        anomalies.append(("userAgent", user_agent))

    if region and region not in baseline.get("regions", []):
        anomalies.append(("awsRegion", region))

    if service and service not in baseline.get("services", []):
        anomalies.append(("eventSource", service))

    if event_hour and not allowed_hours:
        trusted_hours = baseline.get("work_hours_utc", [])
        if trusted_hours and event_hour not in trusted_hours:
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

