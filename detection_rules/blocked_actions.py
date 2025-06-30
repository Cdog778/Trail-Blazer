def detect_blocked_action(record, baseline, write_alert):
    event_name = record.get("eventName")
    error_code = record.get("errorCode")
    if error_code != "AccessDenied":
        return

    username = record.get("userIdentity", {}).get("userName", "unknown")
    source_ip = record.get("sourceIPAddress", "unknown")
    region = record.get("awsRegion", "unknown")
    event_time_str = record.get("eventTime")

    print(f"[ALERT] Blocked action detected: {event_name} by {username}")
    write_alert(
        alert_type="Blocked Action",
        metadata={
            "severity": "low",
            "category": "iam",
            "actor_type": "human",
            "timestamp": event_time_str
        },
        details={
            "user": username,
            "event": event_name,
            "source_ip": source_ip,
            "region": region,
            "error_code": error_code
        }
    )

