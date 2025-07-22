resource "aws_sqs_queue" "detection" {
  name                      = "detection-queue"
  visibility_timeout_seconds = 300
}

resource "aws_sqs_queue" "baseline" {
  name                      = "baseline-queue"
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

data "aws_iam_policy_document" "sns_to_sqs" {
  statement {
    actions = ["sqs:SendMessage"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    resources = [
      aws_sqs_queue.detection.arn,
      aws_sqs_queue.baseline.arn
    ]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sns_topic.cloudtrail_events.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "detection_policy" {
  queue_url = aws_sqs_queue.detection.id
  policy    = data.aws_iam_policy_document.sns_to_sqs.json
}

resource "aws_sqs_queue_policy" "baseline_policy" {
  queue_url = aws_sqs_queue.baseline.id
  policy    = data.aws_iam_policy_document.sns_to_sqs.json
}

