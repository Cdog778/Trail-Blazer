SUPPRESSION_CONFIG = {
    "user_agents": ["Console", "Mozilla"],
    "usernames": ["unknown"]
}

def is_suppressed(username, user_agent):
    if username in SUPPRESSION_CONFIG["usernames"]:
        return True
    if any(pattern in user_agent for pattern in SUPPRESSION_CONFIG["user_agents"]):
        return True
    return False

