from utils.alert_writer import write_alert

def detect_region_anomaly(record, baseline, write_alert_fn=write_alert):
    username = record.get("userIdentity", {}).get("userName", "unknown")
    region = record.get("awsRegion", "unknown")
    timestamp = record.get("eventTime", "unknown")
    source_ip = record.get("sourceIPAddress", "unknown")
    user_agent = record.get("userAgent", "unknown")

    if region not in baseline.get("regions_used", []):
        print(f"[ALERT] Unknown region for user {username}: {region}")
        write_alert_fn(
            alert_type="Region Not in Baseline",
            metadata={
                "severity": "medium",
                "category": "geo",
                "actor_type": "human",
                "timestamp": timestamp
            },
            details={
                "user": username,
                "source_ip": source_ip,
                "region": region,
                "user_agent": user_agent
            }
        )

