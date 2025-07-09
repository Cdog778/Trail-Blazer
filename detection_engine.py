import boto3
import json
import gzip
from datetime import datetime

from utils.config_loader import load_config
from utils.suppression import is_suppressed
from utils.alert_writer import write_alert

from rules.assume_role import detect_assume_role
from rules.privilege_escalation import detect_privilege_escalation
from rules.s3_exposure import detect_s3_exposure
from rules.blocked_actions import detect_blocked_action
from rules.ip_anomaly import detect_ip_anomaly
from rules.region_anomaly import detect_region_anomaly
from rules.hour_behavior import detect_hour_behavior

# === Load config ===
config = load_config()
REGION = config["aws"]["region"]
BUCKET = config["s3"]["log_bucket"]
TABLE_NAME = config["dynamodb"]["baseline_table"]
QUEUE_URL = config["sqs"]["detection_queue_url"]

# === AWS Clients ===
dynamodb = boto3.resource("dynamodb", region_name=REGION)
s3 = boto3.client("s3", region_name=REGION)
sqs = boto3.client("sqs", region_name=REGION)
table = dynamodb.Table(TABLE_NAME)

def normalize_user(identity):
    return identity.get("userName") or identity.get("principalId") or "unknown"

def process_log_file(bucket, key):
    try:
        print(f"[INFO] Processing: {key}", flush=True)
        obj = s3.get_object(Bucket=bucket, Key=key)
        data = gzip.decompress(obj["Body"].read()).decode("utf-8")
        log_data = json.loads(data)

        for record in log_data.get("Records", []):
            identity = record.get("userIdentity", {})
            username = normalize_user(identity)
            user_agent = record.get("userAgent", "unknown")

            if is_suppressed(username, user_agent):
                print(f"[SKIP] Suppressed {username}/{user_agent}", flush=True)
                continue

            baseline = table.get_item(Key={"username": username}).get("Item", {})

            detect_assume_role(record, baseline, write_alert)
            detect_privilege_escalation(record, baseline, write_alert)
            detect_s3_exposure(record, baseline, write_alert)
            detect_blocked_action(record, baseline, write_alert)
            detect_ip_anomaly(record, baseline, write_alert)
            detect_region_anomaly(record, baseline, write_alert)
            detect_hour_behavior(record, baseline, write_alert)

    except Exception as e:
        print(f"[ERROR] Failed to process log file {key}: {e}", flush=True)

def main():
    print("[BOOT] Detection engine started. Polling SQS...", flush=True)

    while True:
        try:
            resp = sqs.receive_message(
                QueueUrl=QUEUE_URL,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20
            )

            for msg in resp.get("Messages", []):
                try:
                    body = json.loads(msg["Body"])
                    msg_data = json.loads(body["Message"])
                    key = msg_data["Records"][0]["s3"]["object"]["key"]

                    process_log_file(BUCKET, key)

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

