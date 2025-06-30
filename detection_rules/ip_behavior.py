def detect_ip_anomaly(record, baseline, write_alert_fn):
    username = record.get("userIdentity", {}).get("userName", "unknown")
    source_ip = record.get("sourceIPAddress", "unknown")
    timestamp = record.get("eventTime", "unknown")
    user_agent = record.get("userAgent", "unknown")
    region = record.get("awsRegion", "unknown")

    if not baseline:
        return  # baseline missing — handled separately

    if source_ip not in baseline.get("known_ips", []):
        print(f"[ALERT] Unknown IP for user {username}: {source_ip}")
        write_alert_fn(
            alert_type="IP Not in Baseline",
            metadata={
                "severity": "high",
                "category": "iam",
                "actor_type": "human",
                "timestamp": timestamp
            },
            details={
                "user": username,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "region": region
            }
        )

