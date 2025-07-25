# -----------------------------------
# GitHub OIDC Provider (Required for GitHub Actions)
# -----------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "github_oidc_trust" {
  statement {
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:Cdog778/Trail-Blazer:*"] # Replace if your GitHub repo changes
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

# -----------------------------------
# ECS Execution Role (Fargate)
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
# Baseline Task Role + Inline Policy
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
      {
        Effect = "Allow",
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ],
        Resource = "arn:aws:sqs:${var.aws_region}:${var.account_id}:${var.baseline_queue_name}"
      },
      {
        Effect = "Allow",
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ],
        Resource = "arn:aws:dynamodb:${var.aws_region}:${var.account_id}:table/${var.baseline_table_name}"
      },
      {
        Effect   = "Allow",
        Action   = ["s3:GetObject"],
        Resource = "arn:aws:s3:::${var.cloudtrail_bucket_name}/AWSLogs/${var.account_id}/*"
      },
      {
        Effect   = "Allow",
        Action   = ["s3:PutObject"],
        Resource = "arn:aws:s3:::${var.alert_bucket_name}/*"
      }
    ]
  })
}

# -----------------------------------
# Detection Task Role + Inline Policy
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
      {
        Effect = "Allow",
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ],
        Resource = "arn:aws:sqs:${var.aws_region}:${var.account_id}:${var.detection_queue_name}"
      },
      {
        Effect = "Allow",
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Scan"
        ],
        Resource = "arn:aws:dynamodb:${var.aws_region}:${var.account_id}:table/${var.baseline_table_name}"
      },
      {
        Effect   = "Allow",
        Action   = ["s3:PutObject"],
        Resource = "arn:aws:s3:::${var.alert_bucket_name}/*"
      },
      {
        Effect   = "Allow",
        Action   = ["s3:GetObject"],
        Resource = "arn:aws:s3:::${var.cloudtrail_bucket_name}/AWSLogs/${var.account_id}/*"
      }
    ]
  })
}

