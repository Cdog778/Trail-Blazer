# -----------------------------------
# ECS Execution Role (for Fargate tasks to pull images and write logs)
# -----------------------------------
resource "aws_iam_role" "ecs_execution_role" {
  name = "ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_role_policy" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# -----------------------------------
# Detection Engine Task Role + Policy
# -----------------------------------
resource "aws_iam_role" "detection_task_role" {
  name = "detection-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "detection_task_policy" {
  role = aws_iam_role.detection_task_role.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Read from detection SQS queue
      {
        Effect = "Allow",
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ],
        Resource = "arn:aws:sqs:us-east-2:732406385148:detection-queue"
      },
      # Read from DynamoDB baseline table
      {
        Effect = "Allow",
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Scan"
        ],
        Resource = "arn:aws:dynamodb:us-east-2:732406385148:table/BaselineData"
      },
      # Write alerts to S3
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject"
        ],
        Resource = "arn:aws:s3:::anomaly-alerts-84917/*"
      },
      # Read CloudTrail logs from S3
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject"
        ],
        Resource = "arn:aws:s3:::cloudtrail-logs-84917/AWSLogs/732406385148/*"
      }
    ]
  })
}

# -----------------------------------
# Baseline Engine Task Role + Policy
# -----------------------------------
resource "aws_iam_role" "baseline_task_role" {
  name = "baseline-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "baseline_task_policy" {
  role = aws_iam_role.baseline_task_role.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Read from baseline SQS queue
      {
        Effect = "Allow",
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ],
        Resource = "arn:aws:sqs:us-east-2:732406385148:baseline-queue"
      },
      # Read/write to DynamoDB baseline table
      {
        Effect = "Allow",
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ],
        Resource = "arn:aws:dynamodb:us-east-2:732406385148:table/BaselineData"
      },
      # Read CloudTrail logs from S3
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject"
        ],
        Resource = "arn:aws:s3:::cloudtrail-logs-84917/AWSLogs/732406385148/*"
      },
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject"
        ],
        Resource = "arn:aws:s3:::anomaly-alerts-84917/*"
      }
    ]
  })
}

data "aws_iam_policy_document" "github_oidc_trust" {
  statement {
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::732406385148:oidc-provider/token.actions.githubusercontent.com"]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:cardell/iam-anomaly-engine:*"]  # ← update if different
    }
  }
}

resource "aws_iam_role" "github_actions_deploy" {
  name               = "GitHubActionsDeployRole"
  assume_role_policy = data.aws_iam_policy_document.github_oidc_trust.json
}

resource "aws_iam_role_policy_attachment" "github_ecr_power" {
  role       = aws_iam_role.github_actions_deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"
}

resource "aws_iam_role_policy_attachment" "github_ecs_access" {
  role       = aws_iam_role.github_actions_deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonECS_FullAccess"
}

