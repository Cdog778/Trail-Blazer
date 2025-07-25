resource "aws_cloudtrail" "main" {
  name                          = "cloudtrail-${var.bucket_suffix}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs_policy
  ]
}
