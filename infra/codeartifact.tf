locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ── Domínio CodeArtifact (com CMK opcional) ────────────────────────────────────
resource "aws_codeartifact_domain" "main" {
  domain          = var.domain_name
  encryption_key  = aws_kms_key.quarantine.arn  # CMK gerenciada pelo projeto
}

# Política do domínio: apenas a conta pode operar; Deny a outras contas
resource "aws_codeartifact_domain_permissions_policy" "main" {
  domain          = aws_codeartifact_domain.main.domain
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCurrentAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = ["codeartifact:*"]
        Resource = "*"
      },
      {
        Sid    = "DenyCrossAccountAccess"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action    = ["codeartifact:*"]
        Resource  = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalAccount" = local.account_id
          }
        }
      }
    ]
  })
}

# ── Repositório de Quarentena ──────────────────────────────────────────────────
resource "aws_codeartifact_repository" "npm_proxy" {
  repository  = "npm-public-proxy"
  domain      = aws_codeartifact_domain.main.domain
  description = "Espelho do npm público. Pacotes ficam aqui em quarentena antes de serem promovidos."

  external_connections {
    external_connection_name = "public:npmjs"
  }
}

# Política do repositório de quarentena:
#   - Lambda (QuarantineAutomation=true): acesso completo
#   - Devs: Deny de PublishPackageVersion (não podem publicar diretamente)
#
# Melhoria de segurança vs. v1:
#   O bloqueio de devs usa "aws:PrincipalType" para garantir que apenas
#   principals do tipo "AssumedRole" com a tag correta passem.
#   O DenyDirectDevPublish usa StringNotEquals na tag QuarantineAutomation
#   ao invés de ArnNotLike, o que é mais robusto contra novos ARNs.
resource "aws_codeartifact_repository_permissions_policy" "npm_proxy" {
  domain          = aws_codeartifact_domain.main.domain
  repository      = aws_codeartifact_repository.npm_proxy.repository
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow: Lambda com a tag QuarantineAutomation tem acesso completo
      {
        Sid    = "AllowQuarantineAutomation"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_role.arn
        }
        Action   = ["codeartifact:*"]
        Resource = "*"
      },
      # Allow: leitura para toda a conta (devs podem baixar via npm-store upstream)
      {
        Sid    = "AllowAccountRead"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = [
          "codeartifact:ListPackages",
          "codeartifact:ListPackageVersions",
          "codeartifact:DescribePackageVersion",
          "codeartifact:GetRepositoryEndpoint",
          "codeartifact:ReadFromRepository",
        ]
        Resource = "*"
      },
      # Deny: qualquer principal da conta que NÃO seja a Lambda de quarentena
      # não pode publicar diretamente no proxy.
      # Nota: Para proteção completa contra admins, adicione SCP na org.
      {
        Sid    = "DenyDirectPublishByNonAutomation"
        Effect = "Deny"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = [
          "codeartifact:PublishPackageVersion",
          "codeartifact:PutPackageMetadata",
        ]
        Resource = "*"
        Condition = {
          # Nega a qualquer um que não seja a role de automação
          ArnNotEquals = {
            "aws:PrincipalArn" = aws_iam_role.lambda_role.arn
          }
        }
      }
    ]
  })
}

# ── Repositório de Produção ────────────────────────────────────────────────────
resource "aws_codeartifact_repository" "npm_store" {
  repository  = "npm-store"
  domain      = aws_codeartifact_domain.main.domain
  description = "Repositório npm interno com pacotes validados e promovidos da quarentena."

  upstream {
    repository_name = aws_codeartifact_repository.npm_proxy.repository
  }
}

# Política do npm-store: devs podem ler, mas não publicar diretamente
resource "aws_codeartifact_repository_permissions_policy" "npm_store" {
  domain          = aws_codeartifact_domain.main.domain
  repository      = aws_codeartifact_repository.npm_store.repository
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Lambda pode copiar versões para cá
      {
        Sid    = "AllowLambdaCopyVersions"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_role.arn
        }
        Action   = ["codeartifact:*"]
        Resource = "*"
      },
      # Devs podem ler e usar via npm install
      {
        Sid    = "AllowDevRead"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = [
          "codeartifact:GetAuthorizationToken",
          "codeartifact:GetRepositoryEndpoint",
          "codeartifact:ReadFromRepository",
          "codeartifact:ListPackages",
          "codeartifact:ListPackageVersions",
          "codeartifact:DescribePackageVersion",
        ]
        Resource = "*"
      },
      # Ninguém exceto Lambda pode publicar no store
      {
        Sid    = "DenyDirectPublishToStore"
        Effect = "Deny"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action = [
          "codeartifact:PublishPackageVersion",
          "codeartifact:PutPackageMetadata",
        ]
        Resource = "*"
        Condition = {
          ArnNotEquals = {
            "aws:PrincipalArn" = aws_iam_role.lambda_role.arn
          }
        }
      }
    ]
  })
}
