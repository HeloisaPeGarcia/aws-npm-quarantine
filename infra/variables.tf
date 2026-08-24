variable "domain_name" {
  description = "Nome do domínio CodeArtifact (deve ser único na conta AWS)"
  type        = string
  default     = "minha-empresa"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,47}$", var.domain_name))
    error_message = "domain_name: 2-48 chars, começar com letra minúscula, apenas letras/números/hífens."
  }
}

variable "quarantine_days" {
  description = "Número de dias que um pacote fica em quarentena antes de ser elegível para promoção"
  type        = number
  default     = 5

  validation {
    condition     = var.quarantine_days >= 1 && var.quarantine_days <= 30
    error_message = "quarantine_days deve estar entre 1 e 30."
  }
}

variable "aws_region" {
  description = "Região AWS onde os recursos serão criados"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Ambiente de deploy"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment deve ser: dev, staging ou prod."
  }
}

variable "lambda_schedule_rate" {
  description = "Frequência de execução da Lambda (EventBridge schedule expression)"
  type        = string
  default     = "rate(6 hours)"
}

variable "lambda_timeout" {
  description = "Timeout da Lambda em segundos (máx 900)"
  type        = number
  default     = 300

  validation {
    condition     = var.lambda_timeout >= 60 && var.lambda_timeout <= 900
    error_message = "lambda_timeout deve estar entre 60 e 900 segundos."
  }
}

variable "lambda_memory" {
  description = "Memória da Lambda em MB"
  type        = number
  default     = 256

  validation {
    condition     = contains([128, 256, 512, 1024, 2048], var.lambda_memory)
    error_message = "lambda_memory deve ser: 128, 256, 512, 1024 ou 2048 MB."
  }
}

variable "notification_email" {
  description = "E-mail para receber alertas SNS de pacotes bloqueados (deixe vazio para desabilitar)"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Dias de retenção dos logs no CloudWatch"
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 180, 365], var.log_retention_days)
    error_message = "log_retention_days deve ser um valor válido do CloudWatch Logs."
  }
}

variable "osv_enabled" {
  description = "Habilitar scan de vulnerabilidades via OSV.dev (osv.dev — Google, gratuito)"
  type        = bool
  default     = true
}

variable "osv_fail_open" {
  description = <<-EOT
    Comportamento quando o OSV.dev estiver indisponível:
      false (padrão, recomendado): fail-closed — pacote NÃO é promovido
      true (inseguro): fail-open — pacote é promovido sem verificação
    ATENÇÃO: só altere para true se entender o risco de supply chain.
  EOT
  type        = bool
  default     = false
}

variable "osv_timeout_seconds" {
  description = "Timeout em segundos para chamadas HTTP ao OSV.dev"
  type        = number
  default     = 10
}

variable "osv_max_retries" {
  description = "Número máximo de tentativas HTTP para OSV.dev (com backoff exponencial)"
  type        = number
  default     = 3
}

variable "custom_metrics_enabled" {
  description = "Emitir métricas customizadas no CloudWatch namespace NPMQuarantine"
  type        = bool
  default     = true
}

variable "max_workers" {
  description = "Número máximo de requisições concorrentes (threads) para o scanner e CodeArtifact"
  type        = number
  default     = 10
}

variable "create_vpc" {
  description = <<-EOT
    Criar VPC dedicada com subnets privadas e NAT Gateway para a Lambda.
    Recomendado para produção: Lambda fica isolada, sem IP público,
    e acessa serviços AWS via VPC Endpoints.
    A Lambda ainda precisa de NAT Gateway para chamar api.osv.dev.
  EOT
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  description = "CIDR block da VPC (usado quando create_vpc=true)"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr deve ser um CIDR válido (ex: 10.0.0.0/16)."
  }
}

variable "private_subnet_cidrs" {
  description = "CIDRs das subnets privadas (Lambda) — 2 AZs recomendado"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDRs das subnets públicas (NAT Gateway) — 2 AZs recomendado"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"]
}
