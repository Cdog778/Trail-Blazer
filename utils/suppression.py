SUPPRESSION_CONFIG = {
    "user_agents": ["AWS Internal", "Console", "Mozilla"],
    "usernames": ["unknown"]
}

def is_suppressed(username, user_agent):
    if username in SUPPRESSION_CONFIG["usernames"]:
        print(f"[INFO] Suppressed user: {username}")
        return True
    if any(pattern in user_agent for pattern in SUPPRESSION_CONFIG["user_agents"]):
        print(f"[INFO] Suppressed user agent: {user_agent}")
        return True
    return False

