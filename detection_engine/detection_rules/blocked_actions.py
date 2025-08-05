def detect_blocked_action(record, baseline, write_alert):
    error_code = record.get("errorCode")
    if error_code != "AccessDenied":
        return

    username = record.get("userIdentity", {}).get("userName", "unknown")
    source_ip = record.get("sourceIPAddress", "unknown")
    region = record.get("awsRegion", "unknown")
    event_time = record.get("eventTime")
    service = record.get("eventSource", "unknown").replace(".amazonaws.com", "")
    event_name = record.get("eventName", "unknown")
    action_key = f"{service}:{event_name}"

    # Suppression list for noisy, low-risk AccessDenied events
    SUPPRESSED_BLOCKED_EVENTS = [
        "ec2:Describe*", "ec2:Get*", "ec2:List*",
        "s3:Get*", "s3:List*", "s3:Head*",
        "iam:List*", "iam:Get*",
        "cloudwatch:Get*", "cloudwatch:List*",
        "logs:Get*", "logs:Describe*", "logs:List*",
        "cloudtrail:Get*", "cloudtrail:List*",
        "config:List*", "config:Get*",
        "sts:GetCallerIdentity"
    ]

    def is_suppressed_blocked_event(action_key):
        for suppressed in SUPPRESSED_BLOCKED_EVENTS:
            if suppressed.endswith("*"):
                if action_key.startswith(suppressed[:-1]):
                    return True
            elif action_key == suppressed:
                return True
        return False

    if is_suppressed_blocked_event(action_key):
        return

    print(f"[ALERT] Blocked action detected: {action_key} by {username}", flush=True)

    write_alert(
        alert_type="Blocked Action",
        metadata={
            "severity": "low",
            "category": "iam",
            "actor_type": "human",
            "timestamp": event_time
        },
        details={
            "user": username,
            "event": event_name,
            "service": service,
            "action_key": action_key,
            "source_ip": source_ip,
            "region": region,
            "error_code": error_code
        }
    )

