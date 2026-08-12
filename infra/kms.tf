# ── KMS Key ───────────────────────────────────────────────────────────────────
# Chave KMS única para criptografar: SQS DLQ, SNS Topic e CloudWatch Logs.
# A key policy segue least-privilege: cada serviço tem apenas as ações necessárias.
resource "aws_kms_key" "quarantine" {
  description             = "Chave KMS do npm-quarantine (${var.environment}) — SQS, SNS, CloudWatch"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # rotação automática anual

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Administração da chave pela conta (obrigatório)
      {
        Sid    = "EnableRootAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = ["kms:*"]
        Resource = "*"
      },
      # Lambda: encrypt/decrypt para SQS e SNS
      {
        Sid    = "AllowLambdaUsage"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_role.arn
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
      # CloudWatch Logs: criptografar log streams
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${local.region}:${local.account_id}:*"
          }
        }
      },
      # SNS: criptografar mensagens do tópico
      {
        Sid    = "AllowSNSService"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = "*"
      },
      # CloudWatch Alarms: publicar no SNS criptografado
      {
        Sid    = "AllowCloudWatchAlarms"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "quarantine" {
  name          = "alias/npm-quarantine-${var.environment}"
  target_key_id = aws_kms_key.quarantine.key_id
}
