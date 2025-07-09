import boto3
import gzip
import json
import time
from datetime import datetime
from utils.config_loader import load_config
from utils.suppression import is_suppressed
from utils.baseline import (
    normalize_user,
    record_candidate,
    should_promote_candidate,
    promote_candidate,
    alert_promotion,
)

# --- Load config ---
cfg = load_config()
REGION = cfg["aws"]["region"]
BUCKET = cfg["s3"]["log_bucket"]
PREFIX = cfg["s3"]["log_prefix"]
TABLE_NAME = cfg["dynamodb"]["baseline_table"]
PROM_THRESH = cfg["dynamodb"]["promotion"]
POLL_INTERVAL = cfg["polling"]["interval_seconds"]

# --- AWS clients ---
iam = boto3.client("iam", region_name=REGION)
s3  = boto3.client("s3", region_name=REGION)
ddb = boto3.client("dynamodb", region_name=REGION)
table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)

# --- What fields to track ---
FIELD_MAP = {
  "sourceIPAddress": "known_ips",
  "userAgent":       "user_agents",
  "awsRegion":       "regions",
  "eventSource":     "services"
}

def list_iam_users():
    users = []
    for page in iam.get_paginator("list_users").paginate():
        users += [u["UserName"] for u in page["Users"]]
    return users

def list_log_keys():
    token = None
    while True:
        args = {"Bucket": BUCKET, "Prefix": PREFIX}
        if token: args["ContinuationToken"] = token
        resp = s3.list_objects_v2(**args)
        for obj in resp.get("Contents", []):
            yield obj["Key"]
        if resp.get("IsTruncated"):
            token = resp["NextContinuationToken"]
        else:
            break

def process_log_file(key, iam_set, write_alert):
    obj = s3.get_object(Bucket=BUCKET, Key=key)
    records = json.loads(gzip.decompress(obj["Body"].read()).decode())["Records"]
    for r in records:
        user_id = normalize_user(r.get("userIdentity", {}))
        if user_id not in iam_set:
            continue

        for log_f, base_k in FIELD_MAP.items():
            val = r.get(log_f, "unknown")
            if is_suppressed(user_id, val):
                continue

            # record or increment candidate
            record_candidate(user_id, base_k, val, table, PROM_THRESH)

            # fetch item to check promotion
            item = table.get_item(Key={"username": user_id}).get("Item", {})
            if should_promote_candidate(item, base_k, val, PROM_THRESH):
                promote_candidate(user_id, base_k, val, table)
                alert_promotion(user_id, base_k, val, write_alert)

def main():
    print("[BOOT] Baseline engine (with secure promotions) starting…", flush=True)
    users = list_iam_users()
    iam_set = set(users)
    print(f"[INFO] {len(users)} IAM users found.", flush=True)

    # init profiles if missing
    for u in users:
        ddb.put_item(TableName=TABLE_NAME, Item={"username":{"S":u}})

    seen = set()
    while True:
        new = 0
        for key in list_log_keys():
            if not key.endswith(".json.gz") or "Digest" in key or key in seen:
                continue
            process_log_file(key, iam_set, write_alert)
            seen.add(key)
            new += 1
        print(f"[INFO] Baseline pass complete: {new} new file(s).", flush=True)
        time.sleep(POLL_INTERVAL)

if __name__=="__main__":
    main()

