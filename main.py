import boto3
import gzip
import json
import time
from datetime import datetime
from detection_rules.privilege_escalation import detect_privilege_escalation
from detection_rules.assume_role import detect_assume_role
from detection_rules.s3_exposure import detect_s3_exposure
from detection_rules.blocked_actions import detect_blocked_action
from utils.baseline import get_user_baseline
from utils.alert_writer import write_alert
from utils.suppression import is_suppressed

# === AWS Clients ===
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb", region_name="us-west-1")
processed_table = dynamodb.Table("ProcessedS3Logs")

# === Constants ===
bucket_name = "iam-trail-logs-cardell"
prefix = "AWSLogs/"

# === Processed Key Tracker ===

def has_been_processed(key):
    try:
        response = processed_table.get_item(Key={"log_key": key})
        return "Item" in response
    except Exception as e:
        print(f"[ERROR] DynamoDB read failed for key {key}: {e}", flush=True)
        return False

def mark_as_processed(key):
    try:
        processed_table.put_item(Item={
            "log_key": key,
            "processed_at": datetime.utcnow().isoformat() + "Z"
        })
        print(f"[INFO] Marked as processed: {key}", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to mark {key} in DynamoDB: {e}", flush=True)

# === S3 Paginator ===

def list_all_keys(bucket, prefix):
    continuation_token = None
    while True:
        if continuation_token:
            response = s3.list_objects_v2(
                Bucket=bucket, Prefix=prefix,
                ContinuationToken=continuation_token
            )
        else:
            response = s3.list_objects_v2(
                Bucket=bucket, Prefix=prefix
            )

        for obj in response.get("Contents", []):
            yield obj["Key"]

        if response.get("IsTruncated"):
            continuation_token = response["NextContinuationToken"]
        else:
            break

# === Log Processing ===

def process_log_file(bucket, key):
    try:
        print(f"[INFO] Processing log: {key}", flush=True)
        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()
        data = gzip.decompress(body)
        log_data = json.loads(data)
        print(f"[DEBUG] Parsed {len(log_data.get('Records', []))} records", flush=True)

        for record in log_data.get("Records", []):
            username = record.get("userIdentity", {}).get("userName", "unknown")
            user_agent = record.get("userAgent", "unknown")
            source_ip = record.get("sourceIPAddress", "unknown")
            timestamp = record.get("eventTime", "unknown")
            region = record.get("awsRegion", "unknown")

            print(f"[DEBUG] Record: {record.get('eventName')} by {username}", flush=True)

            if is_suppressed(username, user_agent):
                print(f"[INFO] Suppressed: {username} / {user_agent}", flush=True)
                continue

            baseline = get_user_baseline(username)
            if not baseline:
                write_alert("Missing Baseline", {
                    "severity": "medium", "category": "baseline",
                    "actor_type": "unknown", "timestamp": timestamp
                }, {
                    "user": username, "source_ip": source_ip,
                    "event_name": record.get("eventName", "unknown"),
                    "user_agent": user_agent, "region": region
                })
                continue

            if source_ip not in baseline.get("known_ips", []):
                write_alert("IP Not in Baseline", {
                    "severity": "high", "category": "iam",
                    "actor_type": "human", "timestamp": timestamp
                }, {
                    "user": username, "source_ip": source_ip,
                    "user_agent": user_agent, "region": region
                })

            if user_agent not in baseline.get("known_agents", []):
                write_alert("UserAgent Not in Baseline", {
                    "severity": "medium", "category": "iam",
                    "actor_type": "human", "timestamp": timestamp
                }, {
                    "user": username, "source_ip": source_ip,
                    "user_agent": user_agent, "region": region
                })

            detect_privilege_escalation(record, baseline, write_alert)
            detect_assume_role(record, baseline, write_alert)
            detect_s3_exposure(record, baseline, write_alert)
            detect_blocked_action(record, baseline, write_alert)

        mark_as_processed(key)

    except Exception as e:
        print(f"[ERROR] Failed to process {key}: {e}", flush=True)

# === Main Loop ===

def main():
    print("[BOOT] main.py started.", flush=True)
    print("[BOOT] Polling S3 for CloudTrail logs...", flush=True)

    while True:
        try:
            count = 0
            for key in list_all_keys(bucket_name, prefix):
                print(f"[DEBUG] Evaluating key: {key}", flush=True)
                if not key.endswith(".json.gz") or "Digest" in key:
                    print(f"[SKIP] Not a valid log file: {key}", flush=True)
                    continue
                if has_been_processed(key):
                    print(f"[SKIP] Already processed: {key}", flush=True)
                    continue
                process_log_file(bucket_name, key)
                count += 1
            print(f"[INFO] Completed pass: {count} new file(s) processed", flush=True)
        except Exception as e:
            print(f"[ERROR] Polling loop failed: {e}", flush=True)

        time.sleep(30)

if __name__ == "__main__":
    main()

