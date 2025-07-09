import boto3
import json
import gzip
from datetime import datetime

from utils.config_loader import load_config
from utils.suppression import is_suppressed
from utils.alert_writer import write_alert

from detection_rules.assume_role import detect_assume_role
from detection_rules.privilege_escalation import detect_privilege_escalation
from detection_rules.s3_exposure import detect_s3_exposure
from detection_rules.blocked_actions import detect_blocked_action

config = load_config()
REGION = config["aws"]["region"]
DEFAULT_BUCKET = config["s3"]["log_bucket"]
TABLE_NAME = config["dynamodb"]["baseline_table"]
QUEUE_URL = config["sqs"]["detection_queue_url"]

dynamodb = boto3.resource("dynamodb", region_name=REGION)
s3 = boto3.client("s3", region_name=REGION)
sqs = boto3.client("sqs", region_name=REGION)
table = dynamodb.Table(TABLE_NAME)

def normalize_user(identity):
    return identity.get("userName") or identity.get("principalId") or "unknown"

def process_log_file(bucket, key):
    try:
        print(f"[INFO] Processing S3 object: {key}", flush=True)
        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()
        print(f"[DEBUG] Retrieved object body ({len(body)} bytes)", flush=True)

        data = gzip.decompress(body).decode("utf-8")
        log_data = json.loads(data)
        print(f"[DEBUG] Parsed {len(log_data.get('Records', []))} records from log", flush=True)

        for i, record in enumerate(log_data.get("Records", [])):
            print(f"[DEBUG] Processing record {i+1}", flush=True)
            identity = record.get("userIdentity", {})
            username = normalize_user(identity)
            user_agent = record.get("userAgent", "unknown")

            print(f"[DEBUG] User: {username}, Agent: {user_agent}", flush=True)

            if is_suppressed(username, user_agent):
                print(f"[SKIP] Suppressed {username}/{user_agent}", flush=True)
                continue

            baseline = table.get_item(Key={"username": username}).get("Item", {})
            print(f"[DEBUG] Loaded baseline for {username}: {bool(baseline)}", flush=True)

            detect_assume_role(record, baseline, write_alert)
            detect_privilege_escalation(record, baseline, write_alert)
            detect_s3_exposure(record, baseline, write_alert)
            detect_blocked_action(record, baseline, write_alert)

    except Exception as e:
        print(f"[ERROR] Failed to process log file {key}: {e}", flush=True)

def main():
    print("[BOOT] Detection engine started. Polling SQS...", flush=True)

    while True:
        try:
            print("[DEBUG] Polling SQS queue...", flush=True)
            resp = sqs.receive_message(
                QueueUrl=QUEUE_URL,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20
            )

            messages = resp.get("Messages", [])
            print(f"[DEBUG] Retrieved {len(messages)} messages", flush=True)

            for msg in messages:
                try:
                    body = json.loads(msg["Body"])
                    msg_data = json.loads(body["Message"])

                    for record in msg_data.get("Records", []):
                        bucket = record["s3"]["bucket"]["name"]
                        key = record["s3"]["object"]["key"]
                        print(f"[DEBUG] Extracted bucket/key: {bucket}/{key}", flush=True)
                        process_log_file(bucket, key)

                    print(f"[DEBUG] Deleting message from SQS", flush=True)
                    sqs.delete_message(
                        QueueUrl=QUEUE_URL,
                        ReceiptHandle=msg["ReceiptHandle"]
                    )
                except Exception as e:
                    print(f"[ERROR] Failed to process message: {e}", flush=True)

        except Exception as e:
            print(f"[ERROR] SQS polling failed: {e}", flush=True)

if __name__ == "__main__":
    main()

