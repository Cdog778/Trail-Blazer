resource "aws_dynamodb_table" "baseline_table" {
  name         = "BaselineData"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "username"

  attribute {
    name = "username"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Environment = "prod"
    App         = "iam-anomaly-engine"
  }
}

