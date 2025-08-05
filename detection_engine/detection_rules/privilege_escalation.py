def detect_privilege_escalation(record, baseline, write_alert):
    event_name = record.get("eventName")
    username = record.get("userIdentity", {}).get("userName", "unknown")
    event_time_str = record.get("eventTime")
    source_ip = record.get("sourceIPAddress", "unknown")
    user_agent = record.get("userAgent", "unknown")
    service = record.get("eventSource", "unknown").replace(".amazonaws.com", "")
    action_key = f"{service}:{event_name}"

    suspicious_actions = {
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:PutRolePolicy",
        "iam:CreateAccessKey",
        "iam:CreatePolicy",
        "iam:UpdateAssumeRolePolicy"
    }

    if action_key not in suspicious_actions:
        return

    candidates = baseline.get("candidates", {})

    def is_candidate(field, value):
        return value in candidates.get(field, {})

    is_ip_untrusted = source_ip not in baseline.get("known_ips", []) and not is_candidate("known_ips", source_ip)
    is_agent_untrusted = user_agent not in baseline.get("user_agents", []) and not is_candidate("user_agents", user_agent)
    is_action_unusual = action_key not in baseline.get("actions", []) and not is_candidate("actions", action_key)

    if is_ip_untrusted or is_agent_untrusted or is_action_unusual:
        print(f"[ALERT] Suspicious privilege escalation by {username}: {action_key}", flush=True)
        write_alert(
            alert_type="Suspicious Privilege Escalation",
            metadata={
                "severity": "high",
                "category": "iam",
                "actor_type": "human",
                "timestamp": event_time_str
            },
            details={
                "user": username,
                "event": event_name,
                "action_key": action_key,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "ip_trusted": not is_ip_untrusted,
                "agent_trusted": not is_agent_untrusted,
                "action_baselined": not is_action_unusual
            }
        )

