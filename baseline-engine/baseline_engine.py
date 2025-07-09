import boto3
import gzip
import json
import time
from datetime import datetime

from utils.config_loader import load_config
from utils.suppression import is_suppressed
from utils.baseline import normalize_user

cfg = load_config()
REGION      = cfg["aws"]["region"]
BUCKET      = cfg["s3"]["log_bucket"]
QUEUE_URL   = cfg["sqs"]["baseline_queue_url"]
TABLE_NAME  = cfg["dynamodb"]["baseline_table"]

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

            for raw_key, base_key in FIELD_MAP.items():
                val = record.get(raw_key)
                if not val or is_suppressed(username, val):
                    continue

                table.update_item(
                    Key={"username": username},
                    UpdateExpression=f"ADD {base_key} :v",
                    ExpressionAttributeValues={":v": set([val])}
                )
                print(f"[UPDATE] {username}.{base_key} += {val}", flush=True)

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

