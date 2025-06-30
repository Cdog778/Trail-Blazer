def detect_s3_exposure(record, baseline, write_alert):
    event_name = record.get("eventName")
    username = record.get("userIdentity", {}).get("userName", "unknown")
    source_ip = record.get("sourceIPAddress", "unknown")
    region = record.get("awsRegion", "unknown")
    event_time_str = record.get("eventTime")

    risky_events = ["PutBucketPolicy", "PutBucketAcl", "PutObjectAcl"]
    if event_name in risky_events:
        print(f"[ALERT] S3 exposure risk: {event_name} by {username}")
        write_alert(
            alert_type="S3 Exposure Risk",
            metadata={
                "severity": "high",
                "category": "s3",
                "actor_type": "human",
                "timestamp": event_time_str
            },
            details={
                "user": username,
                "event": event_name,
                "source_ip": source_ip,
                "region": region
            }
        )

