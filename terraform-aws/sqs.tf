resource "aws_sqs_queue" "detection" {
  name                       = var.detection_queue_name
  visibility_timeout_seconds = 300
}

resource "aws_sqs_queue" "baseline" {
  name                       = var.baseline_queue_name
  visibility_timeout_seconds = 300
}

resource "aws_sns_topic_subscription" "detection_sub" {
  topic_arn = aws_sns_topic.cloudtrail_events.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.detection.arn
}

resource "aws_sns_topic_subscription" "baseline_sub" {
  topic_arn = aws_sns_topic.cloudtrail_events.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.baseline.arn
}

# Policy allowing SNS to publish to detection queue
resource "aws_sqs_queue_policy" "detection_policy" {
  queue_url = aws_sqs_queue.detection.id
  policy    = data.aws_iam_policy_document.detection_sqs_policy.json
}

# Policy allowing SNS to publish to baseline queue
resource "aws_sqs_queue_policy" "baseline_policy" {
  queue_url = aws_sqs_queue.baseline.id
  policy    = data.aws_iam_policy_document.baseline_sqs_policy.json
}

# IAM policy for detection SQS permissions
data "aws_iam_policy_document" "detection_sqs_policy" {
  statement {
    actions = ["sqs:SendMessage"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    resources = [
      "arn:aws:sqs:${var.aws_region}:${var.account_id}:${var.detection_queue_name}"
    ]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sns_topic.cloudtrail_events.arn]
    }
  }
}

# IAM policy for baseline SQS permissions
data "aws_iam_policy_document" "baseline_sqs_policy" {
  statement {
    actions = ["sqs:SendMessage"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    resources = [
      "arn:aws:sqs:${var.aws_region}:${var.account_id}:${var.baseline_queue_name}"
    ]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sns_topic.cloudtrail_events.arn]
    }
  }
}

