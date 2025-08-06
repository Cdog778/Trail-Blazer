def detect_unseen_action(record, baseline, write_alert, username):
    event_name = record.get("eventName", "unknown")
    event_time = record.get("eventTime")
    service = record.get("eventSource", "unknown").replace(".amazonaws.com", "")
    service_action = f"{service}:{event_name}"
    region = record.get("awsRegion", "unknown")
    source_ip = record.get("sourceIPAddress", "unknown")
    user_agent = record.get("userAgent", "unknown")

    trusted_actions = baseline.get("actions", [])

    if service_action not in trusted_actions:
        print(f"[ALERT] Unseen API action by {username}: {service_action}", flush=True)
        write_alert(
            alert_type="Unseen API Action",
            metadata={
                "severity": "medium",
                "category": "behavior",
                "actor_type": "human",
                "timestamp": event_time
            },
            details={
                "user": username,
                "event": event_name,
                "service": service,
                "service_action": service_action,
                "region": region,
                "source_ip": source_ip,
                "user_agent": user_agent
            }
        )

