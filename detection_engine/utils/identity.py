import re
from typing import Tuple, Optional

def _final_token(s: str) -> str:
    return re.split(r"[:/]+", s)[-1] if s else s

def classify_identity(identity: Optional[dict]) -> Tuple[str, str]:
    if not identity:
        return ("unknown", "unknown")

    id_type = identity.get("type")

    if id_type == "Root":
        return ("root", "root")

    if id_type == "IAMUser":
        user_name = identity.get("userName")
        if user_name:
            return (user_name, "user")
        arn = identity.get("arn") or identity.get("principalId", "")
        return (_final_token(arn) or "user", "user")

    if id_type in ("Service", "AWSService"):
        svc = identity.get("principalId") or identity.get("arn") or "service.amazonaws.com"
        return (svc, "service")

    if id_type == "Anonymous":
        return ("anonymous", "anonymous")

    if id_type == "AssumedRole":
        issuer = (identity.get("sessionContext", {}) or {}).get("sessionIssuer", {}) or {}
        role_name = issuer.get("userName") or _final_token(issuer.get("arn", ""))
        if role_name:
            return (role_name, "role")
        arn = identity.get("arn") or identity.get("principalId", "")
        m = re.search(r":assumed-role/([^/]+)/", arn or "")
        if m:
            return (m.group(1), "role")
        return (_final_token(arn) or "unknown", "role")

    if id_type in ("FederatedUser", "WebIdentityUser"):
        arn = identity.get("arn") or identity.get("principalId", "")
        return (_final_token(arn) or "federated", "federated")

    if id_type == "AWSAccount":
        acct = identity.get("accountId") or identity.get("principalId") or "account"
        return (str(acct), "account")

    arn = identity.get("arn") or identity.get("principalId", "") or "unknown"
    return (_final_token(arn) or "unknown", "unknown")

