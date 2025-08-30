terraform {
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

variable "aws_region" {
  default = "us-east-1"
}

variable "domain_name" {
  description = "Your domain name for the SandboxSpy server"
  type        = string
}

# EC2 Instance for SandboxSpy Server
resource "aws_instance" "sandboxspy_server" {
  ami           = "ami-0c02fb55731490381" # Amazon Linux 2
  instance_type = "t3.medium"
  key_name      = aws_key_pair.sandboxspy_key.key_name

  vpc_security_group_ids = [aws_security_group.sandboxspy_sg.id]
  
  user_data = templatefile("${path.module}/user_data.sh", {
    api_key = random_password.api_key.result
    domain  = var.domain_name
  })

  tags = {
    Name = "SandboxSpy-Server"
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }
}

# Security Group
resource "aws_security_group" "sandboxspy_sg" {
  name        = "sandboxspy-server-sg"
  description = "Security group for SandboxSpy server"

  # Allow HTTP from CloudFront only
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Will restrict to CloudFront IPs
  }

  # Allow HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH for management
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["YOUR_IP/32"] # Replace with your IP
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Generate API Key
resource "random_password" "api_key" {
  length  = 32
  special = false
}

# SSH Key
resource "aws_key_pair" "sandboxspy_key" {
  key_name   = "sandboxspy-key"
  public_key = file("~/.ssh/id_rsa.pub")
}

# S3 Bucket for CloudFront logs and blocklist storage
resource "aws_s3_bucket" "sandboxspy_storage" {
  bucket = "sandboxspy-${random_id.bucket_suffix.hex}"
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_public_access_block" "sandboxspy_storage" {
  bucket = aws_s3_bucket.sandboxspy_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "sandboxspy_cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = ""
  aliases             = [var.domain_name]

  origin {
    domain_name = aws_instance.sandboxspy_server.public_ip
    origin_id   = "sandboxspy-origin"

    custom_origin_config {
      http_port              = 8080
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "X-CloudFront-Secret"
      value = random_password.cloudfront_secret.result
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "sandboxspy-origin"

    forwarded_values {
      query_string = true
      headers      = ["*"]

      cookies {
        forward = "all"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
    compress               = true
  }

  # Cache behavior for dashboard static files
  ordered_cache_behavior {
    path_pattern     = "/dashboard/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "sandboxspy-origin"

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # WebSocket support
  ordered_cache_behavior {
    path_pattern     = "/ws"
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "sandboxspy-origin"

    forwarded_values {
      query_string = true
      headers      = ["*"]
      
      cookies {
        forward = "all"
      }
    }

    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
    viewer_protocol_policy = "redirect-to-https"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.sandboxspy_cert.arn
    ssl_support_method  = "sni-only"
  }

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.sandboxspy_storage.bucket_domain_name
    prefix          = "cloudfront-logs/"
  }

  tags = {
    Name = "SandboxSpy-CloudFront"
  }
}

# CloudFront secret for origin verification
resource "random_password" "cloudfront_secret" {
  length  = 32
  special = false
}

# ACM Certificate for CloudFront
resource "aws_acm_certificate" "sandboxspy_cert" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# Route53 for DNS (optional - if you're using Route53)
resource "aws_route53_zone" "sandboxspy_zone" {
  name = var.domain_name
}

resource "aws_route53_record" "sandboxspy_record" {
  zone_id = aws_route53_zone.sandboxspy_zone.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.sandboxspy_cdn.domain_name
    zone_id                = aws_cloudfront_distribution.sandboxspy_cdn.hosted_zone_id
    evaluate_target_health = false
  }
}

# RDS for production database (optional - better than SQLite for production)
resource "aws_db_instance" "sandboxspy_db" {
  identifier     = "sandboxspy-db"
  engine         = "postgres"
  engine_version = "15.3"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_encrypted     = true
  
  db_name  = "sandboxspy"
  username = "sandboxspy"
  password = random_password.db_password.result
  
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "sandboxspy-final-snapshot-${timestamp()}"
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_security_group" "rds_sg" {
  name        = "sandboxspy-rds-sg"
  description = "Security group for SandboxSpy RDS"

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.sandboxspy_sg.id]
  }
}

# Outputs
output "cloudfront_url" {
  value = "https://${aws_cloudfront_distribution.sandboxspy_cdn.domain_name}"
}

output "server_ip" {
  value = aws_instance.sandboxspy_server.public_ip
}

output "api_key" {
  value     = random_password.api_key.result
  sensitive = true
}

output "database_endpoint" {
  value = aws_db_instance.sandboxspy_db.endpoint
}