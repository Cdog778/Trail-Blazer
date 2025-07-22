variable "cloudtrail_s3_bucket_name" {
  default = "my-cloudtrail-log-bucket"
}

variable "alerts_bucket_name" {
  default = "anomaly-alert-logs"
}

variable "region" {
  default = "us-east-2"
}

output "private_subnets" {
  value = [aws_subnet.private_a.id]
}

