variable "aws_region" {
  description = "AWS region to deploy to"
  type        = string
}

variable "account_id" {
  description = "AWS account ID (used in ARNs)"
  type        = string
}

variable "bucket_suffix" {
  description = "Globally unique suffix for S3 buckets and queues"
  type        = string
}

variable "deploy_baseline" {
  description = "Whether to deploy the baseline engine and resources"
  type        = bool
  default     = true
}

variable "deploy_detection" {
  description = "Whether to deploy the detection engine and resources"
  type        = bool
  default     = true
}

variable "alert_bucket_name" {
  description = "Name of the S3 bucket to write alerts to (must be globally unique)"
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket that receives CloudTrail logs"
  type        = string
}

variable "cloudtrail_sns_topic_name" {
  description = "SNS topic name for CloudTrail log fanout"
  type        = string
  default     = "cloudtrail-log-events"
}

variable "baseline_queue_name" {
  description = "Name of the baseline engine SQS queue"
  type        = string
  default     = "baseline-queue"
}

variable "detection_queue_name" {
  description = "Name of the detection engine SQS queue"
  type        = string
  default     = "detection-queue"
}

variable "baseline_service_name" {
  description = "ECS service name for the baseline engine"
  type        = string
  default     = "baseline-service"
}

variable "detection_service_name" {
  description = "ECS service name for the detection engine"
  type        = string
  default     = "detection-service"
}

variable "cluster_name" {
  description = "Name of the ECS cluster"
  type        = string
  default     = "anomaly-engine-cluster"
}

variable "baseline_table_name" {
  description = "Name of the DynamoDB table for storing baseline data"
  type        = string
  default     = "BaselineData"
}

