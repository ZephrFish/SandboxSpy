# AWS Secrets Manager Configuration for SandboxSpy

# Random password generation for secrets
resource "random_password" "api_key" {
  length  = 64
  special = true
  override_special = "-_"
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "random_password" "redis_password" {
  length  = 32
  special = true
}

resource "random_password" "cloudfront_secret" {
  length  = 64
  special = false
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

resource "random_password" "encryption_key" {
  length  = 32
  special = false
}

# API Keys Secret
resource "aws_secretsmanager_secret" "api_keys" {
  name                    = "sandboxspy/api-keys"
  description            = "API keys for SandboxSpy"
  recovery_window_in_days = 7
  rotation_rules {
    automatically_after_days = 30
  }

  tags = {
    Application = "SandboxSpy"
    Environment = var.environment
    Rotation    = "30days"
  }
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id = aws_secretsmanager_secret.api_keys.id
  secret_string = jsonencode({
    default  = random_password.api_key.result
    premium1 = random_password.api_key.result
    premium2 = random_password.api_key.result
    readonly = random_password.api_key.result
  })
}

# Database Credentials Secret
resource "aws_secretsmanager_secret" "database" {
  name                    = "sandboxspy/database"
  description            = "Database credentials for SandboxSpy"
  recovery_window_in_days = 7
  rotation_rules {
    automatically_after_days = 90
  }

  tags = {
    Application = "SandboxSpy"
    Environment = var.environment
    Rotation    = "90days"
  }
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username = "sandboxspy"
    password = random_password.db_password.result
    host     = aws_db_instance.sandboxspy.address
    port     = 5432
    database = "sandboxspy"
  })
}

# Redis Credentials Secret
resource "aws_secretsmanager_secret" "redis" {
  name                    = "sandboxspy/redis"
  description            = "Redis credentials for SandboxSpy"
  recovery_window_in_days = 7
  rotation_rules {
    automatically_after_days = 60
  }

  tags = {
    Application = "SandboxSpy"
    Environment = var.environment
    Rotation    = "60days"
  }
}

resource "aws_secretsmanager_secret_version" "redis" {
  secret_id = aws_secretsmanager_secret.redis.id
  secret_string = jsonencode({
    password = random_password.redis_password.result
    host     = aws_elasticache_cluster.sandboxspy.cache_nodes[0].address
    port     = 6379
  })
}

# CloudFront Secret
resource "aws_secretsmanager_secret" "cloudfront" {
  name                    = "sandboxspy/cloudfront"
  description            = "CloudFront origin verification secret"
  recovery_window_in_days = 7
  rotation_rules {
    automatically_after_days = 180
  }

  tags = {
    Application = "SandboxSpy"
    Environment = var.environment
    Rotation    = "180days"
  }
}

resource "aws_secretsmanager_secret_version" "cloudfront" {
  secret_id = aws_secretsmanager_secret.cloudfront.id
  secret_string = jsonencode({
    secret = random_password.cloudfront_secret.result
  })
}

# JWT and Encryption Keys
resource "aws_secretsmanager_secret" "encryption" {
  name                    = "sandboxspy/encryption"
  description            = "Encryption and signing keys for SandboxSpy"
  recovery_window_in_days = 7
  rotation_rules {
    automatically_after_days = 365
  }

  tags = {
    Application = "SandboxSpy"
    Environment = var.environment
    Rotation    = "365days"
  }
}

resource "aws_secretsmanager_secret_version" "encryption" {
  secret_id = aws_secretsmanager_secret.encryption.id
  secret_string = jsonencode({
    jwt_secret         = random_password.jwt_secret.result
    jwt_refresh_secret = random_password.jwt_secret.result
    encryption_key     = random_password.encryption_key.result
    signing_key        = random_password.encryption_key.result
  })
}

# Lambda function for automatic rotation
resource "aws_lambda_function" "rotate_secrets" {
  filename         = "rotate_secrets.zip"
  function_name    = "sandboxspy-rotate-secrets"
  role            = aws_iam_role.lambda_rotation.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 30

  environment {
    variables = {
      SECRETS_PREFIX = "sandboxspy/"
    }
  }

  tags = {
    Application = "SandboxSpy"
    Environment = var.environment
  }
}

# IAM role for Lambda rotation function
resource "aws_iam_role" "lambda_rotation" {
  name = "sandboxspy-lambda-rotation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM policy for Lambda rotation function
resource "aws_iam_role_policy" "lambda_rotation" {
  name = "sandboxspy-lambda-rotation-policy"
  role = aws_iam_role.lambda_rotation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:sandboxspy/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# IAM role for ECS tasks to access secrets
resource "aws_iam_role" "ecs_task_execution" {
  name = "sandboxspy-ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# IAM policy for ECS tasks to access secrets
resource "aws_iam_role_policy" "ecs_secrets_access" {
  name = "sandboxspy-ecs-secrets-policy"
  role = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:sandboxspy/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Output the secret ARNs for use in other resources
output "api_keys_secret_arn" {
  value = aws_secretsmanager_secret.api_keys.arn
}

output "database_secret_arn" {
  value = aws_secretsmanager_secret.database.arn
}

output "redis_secret_arn" {
  value = aws_secretsmanager_secret.redis.arn
}

output "cloudfront_secret_arn" {
  value = aws_secretsmanager_secret.cloudfront.arn
}

output "encryption_secret_arn" {
  value = aws_secretsmanager_secret.encryption.arn
}