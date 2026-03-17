# SENTINEL — AWS ECS Fargate Deployment
# Terraform configuration for production deployment

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "sentinel_image" {
  description = "Docker image URI for SENTINEL"
  type        = string
}

variable "openai_api_key_arn" {
  description = "ARN of the Secrets Manager secret containing the OpenAI API key"
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

resource "aws_vpc" "sentinel" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "sentinel-${var.environment}" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.sentinel.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags                    = { Name = "sentinel-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.sentinel.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true
  tags                    = { Name = "sentinel-public-b" }
}

resource "aws_internet_gateway" "sentinel" {
  vpc_id = aws_vpc.sentinel.id
  tags   = { Name = "sentinel-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.sentinel.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sentinel.id
  }
  tags = { Name = "sentinel-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Security Groups
# ---------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name_prefix = "sentinel-alb-"
  vpc_id      = aws_vpc.sentinel.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "sentinel-alb-sg" }
}

resource "aws_security_group" "ecs" {
  name_prefix = "sentinel-ecs-"
  vpc_id      = aws_vpc.sentinel.id

  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "sentinel-ecs-sg" }
}

# ---------------------------------------------------------------------------
# ALB
# ---------------------------------------------------------------------------

resource "aws_lb" "sentinel" {
  name               = "sentinel-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  tags = { Name = "sentinel-alb" }
}

resource "aws_lb_target_group" "sentinel" {
  name        = "sentinel-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.sentinel.id
  target_type = "ip"

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.sentinel.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.sentinel.arn
  }
}

# ---------------------------------------------------------------------------
# ECS Cluster + Fargate Service
# ---------------------------------------------------------------------------

resource "aws_ecs_cluster" "sentinel" {
  name = "sentinel-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_iam_role" "ecs_execution" {
  name = "sentinel-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_cloudwatch_log_group" "sentinel" {
  name              = "/ecs/sentinel"
  retention_in_days = 30
}

resource "aws_ecs_task_definition" "sentinel" {
  family                   = "sentinel"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name      = "sentinel-api"
    image     = var.sentinel_image
    essential = true

    portMappings = [{
      containerPort = 8000
      hostPort      = 8000
      protocol      = "tcp"
    }]

    environment = [
      { name = "SENTINEL_LOG_LEVEL", value = "INFO" },
      { name = "SENTINEL_AUTH_ENABLED", value = "true" },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.sentinel.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

resource "aws_ecs_service" "sentinel" {
  name            = "sentinel-api"
  cluster         = aws_ecs_cluster.sentinel.id
  task_definition = aws_ecs_task_definition.sentinel.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.public_a.id, aws_subnet.public_b.id]
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.sentinel.arn
    container_name   = "sentinel-api"
    container_port   = 8000
  }

  depends_on = [aws_lb_listener.http]
}

# ---------------------------------------------------------------------------
# S3 for log storage
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "logs" {
  bucket = "sentinel-logs-${var.environment}"
  tags   = { Name = "sentinel-logs" }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "alb_dns_name" {
  description = "ALB DNS name for the SENTINEL API"
  value       = aws_lb.sentinel.dns_name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.sentinel.name
}

output "s3_log_bucket" {
  value = aws_s3_bucket.logs.id
}
