def detect_privilege_escalation(record, baseline, write_alert):
    event_name = record.get("eventName")
    username = record.get("userIdentity", {}).get("userName", "unknown")
    event_time_str = record.get("eventTime")

    # Privilege escalation API calls
    suspicious_events = [
        "AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy",
        "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy"
    ]

    if event_name in suspicious_events:
        print(f"[ALERT] Privilege escalation attempt: {event_name} by {username}")
        write_alert(
            alert_type="Privilege Escalation",
            metadata={
                "severity": "high",
                "category": "iam",
                "actor_type": "human",  # could later be dynamic
                "timestamp": event_time_str
            },
            details={
                "user": username,
                "event": event_name
            }
        )

