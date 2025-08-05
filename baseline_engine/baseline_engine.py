import boto3
import gzip
import json
import time
from datetime import datetime

#test
from utils.config_loader import load_config
from utils.suppression import is_suppressed
from utils.baseline import (
    normalize_user,
    record_candidate,
    should_promote_candidate,
    promote_candidate,
    alert_promotion
)
from utils.alert_writer import write_alert

cfg = load_config()
REGION      = cfg["aws"]["region"]
BUCKET      = cfg["s3"]["log_bucket"]
QUEUE_URL   = cfg["sqs"]["baseline_queue_url"]
TABLE_NAME  = cfg["dynamodb"]["baseline_table"]
PROM_THRESH = cfg["dynamodb"]["promotion"]

s3    = boto3.client("s3", region_name=REGION)
sqs   = boto3.client("sqs", region_name=REGION)
ddb   = boto3.resource("dynamodb", region_name=REGION)
table = ddb.Table(TABLE_NAME)

FIELD_MAP = {
    "sourceIPAddress": "known_ips",
    "awsRegion":       "regions",
    "userAgent":       "user_agents",
    "eventSource":     "services"
}

def process_log_file(bucket, key):
    print(f"[INFO] Processing: {bucket}/{key}", flush=True)
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        body = gzip.decompress(obj["Body"].read()).decode("utf-8")
        log_data = json.loads(body)
    except Exception as e:
        print(f"[ERROR] Failed to load log: {e}", flush=True)
        return

    for i, record in enumerate(log_data.get("Records", [])):
        try:
            identity = record.get("userIdentity", {})
            username = normalize_user(identity)
            if username == "unknown":
                continue

            item = table.get_item(Key={"username": username}).get("Item", {})
        if not item:
            now = datetime.utcnow().isoformat() + "Z"
            print(f"[INFO] New user detected: {username}, setting first_seen = {now}", flush=True)
            table.put_item(Item={"username": username, "first_seen": now})
            item = {"username": username, "first_seen": now}

            # Baseline fields
            for raw_key, base_key in FIELD_MAP.items():
                val = record.get(raw_key)
                if not val or is_suppressed(username, val):
                    continue

                record_candidate(username, base_key, val, table, PROM_THRESH)

                item = table.get_item(Key={"username": username}).get("Item", {})
                if should_promote_candidate(item, base_key, val, PROM_THRESH):
                    promote_candidate(username, base_key, val, table)
                    alert_promotion(username, base_key, val, write_alert)

            # Baseline work-hours
            timestamp = record.get("eventTime")
            if timestamp:
                try:
                    event_hour = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
                    hour_str = str(event_hour).zfill(2)
                    record_candidate(username, "work_hours_utc", hour_str, table, PROM_THRESH)

                    item = table.get_item(Key={"username": username}).get("Item", {})
                    if should_promote_candidate(item, "work_hours_utc", hour_str, PROM_THRESH):
                        promote_candidate(username, "work_hours_utc", hour_str, table)
                        alert_promotion(username, "work_hours_utc", hour_str, write_alert)
                except Exception as e:
                    print(f"[WARN] Could not parse eventTime for work-hours: {e}", flush=True)

            # Baseline assumed role ARNs
            if record.get("eventName") == "AssumeRole":
                role_arn = record.get("requestParameters", {}).get("roleArn")
                if role_arn:
                    record_candidate(username, "assumed_roles", role_arn, table, PROM_THRESH)

                    item = table.get_item(Key={"username": username}).get("Item", {})
                    if should_promote_candidate(item, "assumed_roles", role_arn, PROM_THRESH):
                        promote_candidate(username, "assumed_roles", role_arn, table)
                        alert_promotion(username, "assumed_roles", role_arn, write_alert)

            # Baseline service actions
            service = record.get("eventSource", "unknown").replace(".amazonaws.com", "")
            action = record.get("eventName", "unknown")
            service_action = f"{service}:{action}"

            record_candidate(username, "actions", service_action, table, PROM_THRESH)

            item = table.get_item(Key={"username": username}).get("Item", {})
            if should_promote_candidate(item, "actions", service_action, PROM_THRESH):
                promote_candidate(username, "actions", service_action, table)
                alert_promotion(username, "actions", service_action, write_alert)

        except Exception as e:
            print(f"[ERROR] Failed to process record {i + 1}: {e}", flush=True)

def main():
    print("[BOOT] Baseline builder starting ...", flush=True)
    while True:
        try:
            resp = sqs.receive_message(
                QueueUrl=QUEUE_URL,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20
            )
            messages = resp.get("Messages", [])
            print(f"[DEBUG] Received {len(messages)} messages", flush=True)

            for msg in messages:
                try:
                    body = json.loads(msg["Body"])
                    msg_data = json.loads(body.get("Message", "{}"))
                    for record in msg_data.get("Records", []):
                        bucket = record["s3"]["bucket"]["name"]
                        key    = record["s3"]["object"]["key"]
                        process_log_file(bucket, key)

                    sqs.delete_message(
                        QueueUrl=QUEUE_URL,
                        ReceiptHandle=msg["ReceiptHandle"]
                    )
                except Exception as e:
                    print(f"[ERROR] Message processing failed: {e}", flush=True)

        except Exception as e:
            print(f"[ERROR] SQS polling failed: {e}", flush=True)
        time.sleep(1)

if __name__ == "__main__":
    main()

