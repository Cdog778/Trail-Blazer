resource "aws_ecs_cluster" "main" {
  name = "anomaly-engine-cluster"
}

resource "aws_ecs_task_definition" "detection_engine" {
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
      image = "732406385148.dkr.ecr.us-east-2.amazonaws.com/detection-engine:latest"
      essential = true
      environment = [
        { name = "QUEUE_URL", value = aws_sqs_queue.detection.id },
        { name = "BASELINE_TABLE", value = "BaselineData" }, # can replace with variable
        { name = "ALERT_BUCKET", value = "anomaly-alert-logs" }
      ]
      logConfiguration = {
        logDriver = "awslogs",
        options   = {
          awslogs-group         = "/ecs/detection"
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "detection" {
  name            = "detection-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.detection_engine.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = [aws_subnet.private_a.id]
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  depends_on = [aws_iam_role_policy_attachment.ecs_execution_role_policy]
}

resource "aws_ecs_task_definition" "baseline_engine" {
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
      image = "732406385148.dkr.ecr.us-east-2.amazonaws.com/baseline-engine:latest"
      essential = true
      environment = [
        { name = "QUEUE_URL", value = aws_sqs_queue.baseline.id },
        { name = "BASELINE_TABLE", value = "BaselineData" }
      ]
      logConfiguration = {
        logDriver = "awslogs",
        options   = {
          awslogs-group         = "/ecs/baseline"
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "baseline" {
  name            = "baseline-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.baseline_engine.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = [aws_subnet.private_a.id]
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  depends_on = [aws_iam_role_policy_attachment.ecs_execution_role_policy]
}

resource "aws_cloudwatch_log_group" "detection" {
  name              = "/ecs/detection"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "baseline" {
  name              = "/ecs/baseline"
  retention_in_days = 14
}

