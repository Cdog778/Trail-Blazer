# -----------------------------------
# CloudTrail Logs Bucket
# -----------------------------------
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "cloudtrail-logs-84917"
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Environment = "prod"
    App         = "iam-anomaly-engine"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.bucket

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 365
    }
  }
}

# Bucket Policy Required for CloudTrail
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action    = "s3:GetBucketAcl",
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# S3 → SNS Notification for new CloudTrail logs
resource "aws_s3_bucket_notification" "cloudtrail_logs_notify" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  topic {
    topic_arn = aws_sns_topic.cloudtrail_events.arn
    events    = ["s3:ObjectCreated:Put"]
  }

  depends_on = [
    aws_s3_bucket.cloudtrail_logs,
    aws_sns_topic.cloudtrail_events,
    aws_s3_bucket_policy.cloudtrail_logs_policy
  ]
}

# -----------------------------------
# Alerts Bucket for Detection Engine
# -----------------------------------
resource "aws_s3_bucket" "alerts" {
  bucket = "anomaly-alerts-84917"
  force_destroy = false

  tags = {
    Environment = "prod"
    App         = "iam-anomaly-engine"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alerts" {
  bucket = aws_s3_bucket.alerts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alerts" {
  bucket = aws_s3_bucket.alerts.id

  rule {
    id     = "expire-alerts"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 180
    }
  }
}

