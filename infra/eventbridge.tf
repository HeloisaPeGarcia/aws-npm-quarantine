# ── Regra de agendamento ───────────────────────────────────────────────────────
resource "aws_cloudwatch_event_rule" "package_check_schedule" {
  name                = "npm-quarantine-check-${var.environment}"
  description         = "Dispara a Lambda de promoção de pacotes npm a cada X horas"
  schedule_expression = var.lambda_schedule_rate
  state               = "ENABLED"
}

resource "aws_cloudwatch_event_target" "trigger_lambda" {
  rule      = aws_cloudwatch_event_rule.package_check_schedule.name
  target_id = "promote-package-lambda"
  arn       = aws_lambda_function.promote_package.arn

  # Retry policy para reexecutar em caso de throttle
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }

  dead_letter_config {
    arn = aws_sqs_queue.lambda_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.promote_package.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.package_check_schedule.arn
}
