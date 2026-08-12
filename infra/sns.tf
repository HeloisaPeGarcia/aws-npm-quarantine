# ── Tópico SNS (com KMS) ──────────────────────────────────────────────────────
resource "aws_sns_topic" "quarantine_alerts" {
  name              = "npm-quarantine-alerts-${var.environment}"
  display_name      = "NPM Quarantine Alerts"
  kms_master_key_id = aws_kms_key.quarantine.arn  # criptografia em repouso
}

# Inscrição por e-mail (só cria se notification_email for definido)
resource "aws_sns_topic_subscription" "email_alert" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.quarantine_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# Política: Lambda e CloudWatch podem publicar; ninguém mais
resource "aws_sns_topic_policy" "quarantine_alerts" {
  arn = aws_sns_topic.quarantine_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_role.arn
        }
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.quarantine_alerts.arn
      },
      {
        Sid    = "AllowCloudWatchAlarms"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action    = ["sns:Publish"]
        Resource  = aws_sns_topic.quarantine_alerts.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:cloudwatch:${local.region}:${local.account_id}:alarm:*"
          }
        }
      },
      # Deny explícito: ninguém mais pode publicar
      {
        Sid    = "DenyAllOtherPublish"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action    = ["sns:Publish"]
        Resource  = aws_sns_topic.quarantine_alerts.arn
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              aws_iam_role.lambda_role.arn,
              "arn:aws:iam::${local.account_id}:root",
            ]
          }
          StringNotEquals = {
            "aws:PrincipalServiceName" = "cloudwatch.amazonaws.com"
          }
        }
      }
    ]
  })
}
