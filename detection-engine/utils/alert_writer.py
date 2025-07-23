import boto3
import json
import uuid
from datetime import datetime
from utils.config_loader import load_config

# Load settings from config.yaml
cfg = load_config()
REGION = cfg["aws"]["region"]
ALERT_BUCKET = cfg["s3"]["alert_bucket"]
ALERT_PREFIX = cfg["s3"].get("alert_prefix", "alerts")

s3 = boto3.client("s3", region_name=REGION)

def write_alert(alert_type, metadata, details):
    alert = {
        "alert_type": alert_type,
        "severity": metadata.get("severity", "medium"),
        "category": metadata.get("category", "general"),
        "actor_type": metadata.get("actor_type", "unknown"),
        "timestamp": metadata.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        **details
    }

    today = datetime.utcnow().strftime("%Y-%m-%d")
    file_key = f"{ALERT_PREFIX}/{today}/{uuid.uuid4()}.json"

    try:
        s3.put_object(
            Bucket=ALERT_BUCKET,
            Key=file_key,
            Body=json.dumps(alert),
            ContentType="application/json"
        )
        print(f"[S3] Alert written to s3://{ALERT_BUCKET}/{file_key}")
    except Exception as e:
        print(f"[ERROR] Failed to write alert to S3: {e}")

