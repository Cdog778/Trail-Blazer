resource "aws_sns_topic" "cloudtrail_events" {
  name = var.cloudtrail_sns_topic_name
}

data "aws_iam_policy_document" "allow_s3_publish" {
  statement {
    sid    = "AllowS3Publish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = ["SNS:Publish"]

    resources = [aws_sns_topic.cloudtrail_events.arn]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.cloudtrail_logs.arn]
    }
  }
}

resource "aws_sns_topic_policy" "allow_s3_publish" {
  arn    = aws_sns_topic.cloudtrail_events.arn
  policy = data.aws_iam_policy_document.allow_s3_publish.json
}

