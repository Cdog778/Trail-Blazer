resource "aws_ecs_cluster" "main" {
  name = var.cluster_name
}

# -----------------------------------
# CloudWatch Log Groups
# -----------------------------------
resource "aws_cloudwatch_log_group" "baseline" {
  name              = "/ecs/baseline"
  retention_in_days = 30

  tags = {
    App = "iam-anomaly-engine"
  }
}

resource "aws_cloudwatch_log_group" "detection" {
  name              = "/ecs/detection"
  retention_in_days = 30

  tags = {
    App = "iam-anomaly-engine"
  }
}

# -----------------------------------
# Baseline Engine Task Definition
# -----------------------------------
resource "aws_ecs_task_definition" "baseline_engine" {
  count                    = var.deploy_baseline ? 1 : 0
  family                   = "baseline-engine"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.baseline_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "baseline"
      image     = "732406385148.dkr.ecr.${var.aws_region}.amazonaws.com/baseline-engine:latest"
      essential = true
      environment = [
        { name = "QUEUE_URL", value = aws_sqs_queue.baseline.id },
        { name = "BASELINE_TABLE", value = aws_dynamodb_table.baseline_table.name }
      ]
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = aws_cloudwatch_log_group.baseline.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  depends_on = [aws_cloudwatch_log_group.baseline]
}

resource "aws_ecs_service" "baseline" {
  count           = var.deploy_baseline ? 1 : 0
  name            = var.baseline_service_name
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.baseline_engine[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.private_a.id]
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  depends_on = [aws_iam_role_policy.baseline_task_policy]
}

# -----------------------------------
# Detection Engine Task Definition
# -----------------------------------
resource "aws_ecs_task_definition" "detection_engine" {
  count                    = var.deploy_detection ? 1 : 0
  family                   = "detection-engine"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.detection_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "detection"
      image     = "732406385148.dkr.ecr.${var.aws_region}.amazonaws.com/detection-engine:latest"
      essential = true
      environment = [
        { name = "QUEUE_URL", value = aws_sqs_queue.detection.id },
        { name = "BASELINE_TABLE", value = aws_dynamodb_table.baseline_table.name },
        { name = "ALERT_BUCKET", value = var.alert_bucket_name }
      ]
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = aws_cloudwatch_log_group.detection.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  depends_on = [aws_cloudwatch_log_group.detection]
}

resource "aws_ecs_service" "detection" {
  count           = var.deploy_detection ? 1 : 0
  name            = var.detection_service_name
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.detection_engine[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.private_a.id]
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  depends_on = [aws_iam_role_policy.detection_task_policy]
}

