def detect_assume_role(record, baseline, write_alert):
    event_name = record.get("eventName")
    if event_name != "AssumeRole":
        return

    username = record.get("userIdentity", {}).get("userName", "unknown")
    source_ip = record.get("sourceIPAddress", "unknown")
    region = record.get("awsRegion", "unknown")
    event_time_str = record.get("eventTime")
    role_arn = record.get("requestParameters", {}).get("roleArn", "")
    principal_arn = record.get("userIdentity", {}).get("arn", "")

    known_ips = baseline.get("known_ips", [])

    # Check for AssumeRole from unknown IP
    if source_ip not in known_ips:
        print(f"[ALERT] AssumeRole from unknown IP: {source_ip} by {username}")
        write_alert(
            alert_type="AssumeRole from Unknown IP",
            metadata={
                "severity": "high",
                "category": "iam",
                "actor_type": "human",
                "timestamp": event_time_str
            },
            details={
                "user": username,
                "source_ip": source_ip,
                "role_arn": role_arn,
                "principal_arn": principal_arn,
                "region": region
            }
        )

    # Optional: Cross-account AssumeRole
    try:
        role_account = role_arn.split(":")[4]
        user_account = principal_arn.split(":")[4]
        if role_account != user_account:
            print(f"[ALERT] Cross-account AssumeRole detected: {role_arn} by {principal_arn}")
            write_alert(
                alert_type="Cross-Account AssumeRole",
                metadata={
                    "severity": "medium",
                    "category": "iam",
                    "actor_type": "human",
                    "timestamp": event_time_str
                },
                details={
                    "user": username,
                    "role_arn": role_arn,
                    "principal_arn": principal_arn,
                    "region": region
                }
            )
    except Exception as e:
        print(f"[ERROR] Failed to parse account IDs for AssumeRole check: {e}")

