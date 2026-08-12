output "domain_name" {
  description = "Nome do domínio CodeArtifact"
  value       = aws_codeartifact_domain.main.domain
}

output "domain_arn" {
  description = "ARN do domínio CodeArtifact"
  value       = aws_codeartifact_domain.main.arn
}

output "quarantine_repo_name" {
  description = "Nome do repositório de quarentena (npm-public-proxy)"
  value       = aws_codeartifact_repository.npm_proxy.repository
}

output "store_repo_name" {
  description = "Nome do repositório de produção (npm-store)"
  value       = aws_codeartifact_repository.npm_store.repository
}

output "store_repo_endpoint" {
  description = "Endpoint do repositório npm-store (use no .npmrc)"
  value       = "https://${var.domain_name}-${local.account_id}.d.codeartifact.${local.region}.amazonaws.com/npm/${aws_codeartifact_repository.npm_store.repository}/"
}

output "lambda_function_name" {
  description = "Nome da Lambda de promoção"
  value       = aws_lambda_function.promote_package.function_name
}

output "lambda_function_arn" {
  description = "ARN da Lambda de promoção"
  value       = aws_lambda_function.promote_package.arn
}

output "dlq_url" {
  description = "URL da Dead Letter Queue"
  value       = aws_sqs_queue.lambda_dlq.url
}

output "sns_topic_arn" {
  description = "ARN do tópico SNS de alertas"
  value       = aws_sns_topic.quarantine_alerts.arn
}

output "kms_key_arn" {
  description = "ARN da chave KMS de criptografia"
  value       = aws_kms_key.quarantine.arn
}

output "kms_key_alias" {
  description = "Alias da chave KMS"
  value       = aws_kms_alias.quarantine.name
}

output "vpc_id" {
  description = "ID da VPC dedicada (se create_vpc=true)"
  value       = var.create_vpc ? aws_vpc.main[0].id : null
}

output "scanner_provider" {
  description = "Provider de scan de vulnerabilidades em uso"
  value       = "OSV.dev (Google Open Source Vulnerabilities)"
}

output "fail_open_mode" {
  description = "Modo de resiliência do scanner (false = fail-closed, recomendado)"
  value       = var.osv_fail_open
}

output "npmrc_login_command" {
  description = "Comando para configurar o npm apontando pro repositório interno"
  value       = "aws codeartifact login --tool npm --domain ${var.domain_name} --domain-owner ${local.account_id} --repository ${aws_codeartifact_repository.npm_store.repository} --region ${local.region}"
}
