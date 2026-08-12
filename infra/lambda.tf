# Empacota o código Python automaticamente antes de criar/atualizar a Lambda
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  excludes    = ["tests", "tests/*", "__pycache__", "*.pyc", "requirements*.txt", "*.zip"]
  output_path = "${path.module}/../lambda/promote_package.zip"
}

# ── Lambda Function ────────────────────────────────────────────────────────────
resource "aws_lambda_function" "promote_package" {
  function_name    = "promote-quarantined-packages-${var.environment}"
  runtime          = "python3.12"
  handler          = "promote_package.handler"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  role             = aws_iam_role.lambda_role.arn

  environment {
    variables = {
      DOMAIN                  = var.domain_name
      SOURCE_REPO             = aws_codeartifact_repository.npm_proxy.repository
      DEST_REPO               = aws_codeartifact_repository.npm_store.repository
      QUARANTINE_DAYS         = tostring(var.quarantine_days)
      SNS_TOPIC_ARN           = aws_sns_topic.quarantine_alerts.arn
      ENVIRONMENT             = var.environment
      AWS_ACCOUNT_ID          = local.account_id
      # OSV.dev scanner
      OSV_ENABLED             = tostring(var.osv_enabled)
      OSV_FAIL_OPEN           = tostring(var.osv_fail_open)
      OSV_TIMEOUT             = tostring(var.osv_timeout_seconds)
      OSV_MAX_RETRIES         = tostring(var.osv_max_retries)
      # Métricas customizadas
      CUSTOM_METRICS_ENABLED  = tostring(var.custom_metrics_enabled)
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tracing_config {
    mode = "Active"  # X-Ray
  }

  # VPC config — habilitado somente quando create_vpc=true
  dynamic "vpc_config" {
    for_each = var.create_vpc ? [1] : []
    content {
      subnet_ids         = aws_subnet.private[*].id
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_logs,
    aws_cloudwatch_log_group.lambda_logs,
  ]
}

# ── Dead Letter Queue (com KMS) ────────────────────────────────────────────────
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "npm-quarantine-dlq-${var.environment}"
  message_retention_seconds = 1209600  # 14 dias
  kms_master_key_id         = aws_kms_key.quarantine.arn
}

resource "aws_sqs_queue_policy" "lambda_dlq" {
  queue_url = aws_sqs_queue.lambda_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowLambdaDLQ"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.lambda_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_lambda_function.promote_package.arn
        }
      }
    }]
  })
}

# ── CloudWatch Logs (com KMS) ──────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/promote-quarantined-packages-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.quarantine.arn
}

# ── CloudWatch Alarms ──────────────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "npm-quarantine-lambda-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Lambda de promoção de pacotes falhou"
  treat_missing_data  = "notBreaching"

  dimensions = { FunctionName = aws_lambda_function.promote_package.function_name }

  alarm_actions = [aws_sns_topic.quarantine_alerts.arn]
  ok_actions    = [aws_sns_topic.quarantine_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "npm-quarantine-dlq-not-empty-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "DLQ não vazia: Lambda falhou repetidamente"
  treat_missing_data  = "notBreaching"

  dimensions     = { QueueName = aws_sqs_queue.lambda_dlq.name }
  alarm_actions  = [aws_sns_topic.quarantine_alerts.arn]
}

# Alarme: OSV indisponível (falha no scanner)
resource "aws_cloudwatch_metric_alarm" "osv_unavailable" {
  alarm_name          = "npm-quarantine-osv-unavailable-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "OSVUnavailableCount"
  namespace           = "NPMQuarantine"
  period              = 3600
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Scanner OSV.dev indisponível — promoções podem estar bloqueadas (fail-closed)"
  treat_missing_data  = "notBreaching"

  dimensions    = { Environment = var.environment }
  alarm_actions = [aws_sns_topic.quarantine_alerts.arn]
}

# ── IAM Role ───────────────────────────────────────────────────────────────────
resource "aws_iam_role" "lambda_role" {
  name        = "npm-quarantine-lambda-role-${var.environment}"
  description = "Role da Lambda npm-quarantine: promove/bloqueia pacotes"

  # Trust policy: apenas o serviço Lambda pode assumir esta role
  # Isso previne que usuários humanos façam assume-role direto
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowLambdaAssumeRole"
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = {
    # Tag usada como condição no DenyDirectDevPublish do CodeArtifact
    QuarantineAutomation = "true"
  }
}

# CodeArtifact — least-privilege por ações específicas em recursos específicos
resource "aws_iam_role_policy" "lambda_codeartifact" {
  name = "codeartifact-access"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CodeArtifactRead"
        Effect = "Allow"
        Action = [
          "codeartifact:ListPackages",
          "codeartifact:ListPackageVersions",
          "codeartifact:DescribePackageVersion",
          "codeartifact:GetRepositoryEndpoint",
          "codeartifact:ReadFromRepository",
        ]
        Resource = [
          aws_codeartifact_domain.main.arn,
          "${aws_codeartifact_domain.main.arn}/*",
        ]
      },
      {
        Sid    = "CodeArtifactWrite"
        Effect = "Allow"
        Action = [
          "codeartifact:CopyPackageVersions",
          "codeartifact:PutPackageOriginConfiguration",
        ]
        Resource = ["${aws_codeartifact_domain.main.arn}/*"]
      },
      {
        Sid      = "CodeArtifactAuthToken"
        Effect   = "Allow"
        Action   = ["codeartifact:GetAuthorizationToken"]
        Resource = [aws_codeartifact_domain.main.arn]
      },
      {
        Sid      = "STSBearerToken"
        Effect   = "Allow"
        Action   = ["sts:GetServiceBearerToken"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "sts:AWSServiceName" = "codeartifact.amazonaws.com"
          }
        }
      }
    ]
  })
}

# SNS — apenas Publish no tópico específico
resource "aws_iam_role_policy" "lambda_sns" {
  name = "sns-publish"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PublishAlerts"
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = [aws_sns_topic.quarantine_alerts.arn]
    }]
  })
}

# SQS — apenas SendMessage na DLQ específica
resource "aws_iam_role_policy" "lambda_sqs" {
  name = "sqs-dlq"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SendToDLQ"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = [aws_sqs_queue.lambda_dlq.arn]
    }]
  })
}

# CloudWatch — PutMetricData apenas no namespace NPMQuarantine
resource "aws_iam_role_policy" "lambda_cloudwatch" {
  name = "cloudwatch-metrics"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "PutCustomMetrics"
      Effect = "Allow"
      Action = ["cloudwatch:PutMetricData"]
      Resource = "*"
      Condition = {
        StringEquals = {
          "cloudwatch:namespace" = "NPMQuarantine"
        }
      }
    }]
  })
}

# X-Ray tracing
resource "aws_iam_role_policy" "lambda_xray" {
  name = "xray-tracing"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "XRayTracing"
      Effect = "Allow"
      Action = [
        "xray:PutTraceSegments",
        "xray:PutTelemetryRecords",
      ]
      Resource = "*"
    }]
  })
}

# KMS — usar a chave para DLQ e CloudWatch Logs
resource "aws_iam_role_policy" "lambda_kms" {
  name = "kms-usage"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "UseQuarantineKMSKey"
      Effect = "Allow"
      Action = [
        "kms:GenerateDataKey",
        "kms:Decrypt",
        "kms:DescribeKey",
      ]
      Resource = [aws_kms_key.quarantine.arn]
    }]
  })
}

# VPC — necessário para Lambda em subnet privada
resource "aws_iam_role_policy" "lambda_vpc" {
  count = var.create_vpc ? 1 : 0
  name  = "vpc-access"
  role  = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "VPCAccess"
      Effect = "Allow"
      Action = [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface",
        "ec2:AssignPrivateIpAddresses",
        "ec2:UnassignPrivateIpAddresses",
      ]
      Resource = "*"
      Condition = {
        StringEquals = {
          "aws:RequestedRegion" = local.region
        }
      }
    }]
  })
}

# CloudWatch Logs básico (create log streams/events)
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
