import boto3
import json
import uuid
from datetime import datetime

s3 = boto3.client("s3", region_name="us-east-2")
ALERT_BUCKET = "anomaly-alerts-84917"

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
    file_key = f"alerts/{today}/{uuid.uuid4()}.json"

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

