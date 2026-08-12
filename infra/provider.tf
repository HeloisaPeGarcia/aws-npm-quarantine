terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # ── Backend S3 (OBRIGATÓRIO em staging/prod) ────────────────────────────────
  # Descomente e preencha os valores antes de rodar `terraform init`.
  #
  # Pré-requisitos (criar uma única vez):
  #   aws s3 mb s3://COMPANY-terraform-state --region us-east-1
  #   aws s3api put-bucket-versioning \
  #     --bucket COMPANY-terraform-state \
  #     --versioning-configuration Status=Enabled
  #   aws s3api put-bucket-encryption \
  #     --bucket COMPANY-terraform-state \
  #     --server-side-encryption-configuration \
  #     '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
  #   aws dynamodb create-table \
  #     --table-name terraform-lock \
  #     --attribute-definitions AttributeName=LockID,AttributeType=S \
  #     --key-schema AttributeName=LockID,KeyType=HASH \
  #     --billing-mode PAY_PER_REQUEST \
  #     --region us-east-1
  #
  # backend "s3" {
  #   bucket         = "COMPANY-terraform-state"
  #   key            = "npm-quarantine/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-lock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "npm-quarantine"
      ManagedBy   = "terraform"
      Environment = var.environment
      Repository  = "aws-npm-quarantine"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
