def detect_unseen_action(record, baseline, write_alert, username):
    event_name = record.get("eventName")
    service = record.get("eventSource", "unknown").replace(".amazonaws.com", "")
    service_action = f"{service}:{event_name}"

    trusted_actions = baseline.get("actions", [])
    candidates = baseline.get("candidates", {})

    def is_candidate(field, value):
        return value in candidates.get(field, {})

    if service_action not in trusted_actions and not is_candidate("actions", service_action):
        print(f"[ALERT] Unseen API action by {username}: {service_action}", flush=True)
        write_alert(
            alert_type="Unseen API Action",
            metadata={
                "severity": "low",
                "category": "iam",
                "actor_type": "human",
                "timestamp": record.get("eventTime")
            },
            details={
                "user": username,
                "action": service_action,
                "ip": record.get("sourceIPAddress", "unknown"),
                "region": record.get("awsRegion", "unknown"),
                "user_agent": record.get("userAgent", "unknown")
            }
        )

