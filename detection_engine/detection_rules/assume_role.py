def detect_assume_role(record, baseline, write_alert, username):
    event_name = record.get("eventName")
    if event_name != "AssumeRole":
        return

    identity = record.get("userIdentity", {})
    source_ip = record.get("sourceIPAddress", "unknown")
    region = record.get("awsRegion", "unknown")
    user_agent = record.get("userAgent", "unknown")
    event_time = record.get("eventTime")
    role_arn = record.get("requestParameters", {}).get("roleArn", "")
    principal_arn = identity.get("arn", "")

    alerts = []

    candidates = baseline.get("candidates", {})

    def is_candidate(field, value):
        return value in candidates.get(field, {})

    # Unknown IP
    if source_ip not in baseline.get("known_ips", []) and not is_candidate("known_ips", source_ip):
        alerts.append({
            "alert_type": "AssumeRole from Unknown IP",
            "severity": "high",
            "reason": f"IP {source_ip} not in baseline or promotion"
        })

    # Unknown Agent
    if user_agent not in baseline.get("user_agents", []) and not is_candidate("user_agents", user_agent):
        alerts.append({
            "alert_type": "AssumeRole from Unknown Agent",
            "severity": "medium",
            "reason": f"Agent {user_agent} not in baseline or promotion"
        })

    # Unknown RoleArn
    if role_arn and role_arn not in baseline.get("assumed_roles", []) and not is_candidate("assumed_roles", role_arn):
        alerts.append({
            "alert_type": "New Assumed Role",
            "severity": "medium",
            "reason": f"RoleArn {role_arn} not seen before or in promotion"
        })

    # Cross-account AssumeRole
    try:
        role_account = role_arn.split(":")[4]
        user_account = principal_arn.split(":")[4]

        is_cross_account = role_account != user_account
        is_ip_untrusted = source_ip not in baseline.get("known_ips", []) and not is_candidate("known_ips", source_ip)
        is_agent_untrusted = user_agent not in baseline.get("user_agents", []) and not is_candidate("user_agents", user_agent)

        if is_cross_account and (is_ip_untrusted or is_agent_untrusted):
            alerts.append({
                "alert_type": "Cross-Account AssumeRole",
                "severity": "medium",
                "reason": (
                    f"Principal {principal_arn} assumed cross-account role "
                    f"{role_arn} from unknown IP or agent"
                )
            })

    except Exception as e:
        print(f"[ERROR] Failed to parse account IDs for AssumeRole check: {e}", flush=True)

    for alert in alerts:
        print(f"[ALERT] {alert['alert_type']} - {alert['reason']}", flush=True)
        write_alert(
            alert_type=alert["alert_type"],
            metadata={
                "severity": alert["severity"],
                "category": "iam",
                "actor_type": "human",
                "timestamp": event_time
            },
            details={
                "user": username,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "role_arn": role_arn,
                "principal_arn": principal_arn,
                "region": region
            }
        )

