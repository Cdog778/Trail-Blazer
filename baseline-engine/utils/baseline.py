import time
from datetime import datetime

def normalize_user(identity):
    return identity.get("userName") or identity.get("principalId") or "unknown"

