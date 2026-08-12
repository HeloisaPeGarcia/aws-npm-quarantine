# ══════════════════════════════════════════════════════════════════════════════
# VPC — condicional via var.create_vpc
# Habilite em produção para que a Lambda não acesse a internet diretamente.
# A Lambda precisa de NAT Gateway para chamar a API osv.dev (HTTPS externo).
# As APIs AWS (CodeArtifact, SNS, SQS, CW Logs, X-Ray) são acessadas via
# VPC Endpoints — sem tráfego pela internet pública.
# ══════════════════════════════════════════════════════════════════════════════

# ── VPC ───────────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  count = var.create_vpc ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true  # necessário para VPC Endpoints

  tags = { Name = "npm-quarantine-${var.environment}" }
}

# ── Subnets públicas (para NAT Gateway) ───────────────────────────────────────
resource "aws_subnet" "public" {
  count = var.create_vpc ? 2 : 0

  vpc_id            = aws_vpc.main[0].id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available[0].names[count.index]

  map_public_ip_on_launch = false  # nunca IPs públicos automáticos

  tags = { Name = "npm-quarantine-public-${count.index + 1}-${var.environment}" }
}

# ── Subnets privadas (para Lambda) ────────────────────────────────────────────
resource "aws_subnet" "private" {
  count = var.create_vpc ? 2 : 0

  vpc_id            = aws_vpc.main[0].id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available[0].names[count.index]

  tags = { Name = "npm-quarantine-private-${count.index + 1}-${var.environment}" }
}

data "aws_availability_zones" "available" {
  count = var.create_vpc ? 1 : 0
  state = "available"
}

# ── Internet Gateway ──────────────────────────────────────────────────────────
resource "aws_internet_gateway" "main" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  tags = { Name = "npm-quarantine-igw-${var.environment}" }
}

# ── NAT Gateway (permite que a Lambda acesse osv.dev externamente) ─────────────
resource "aws_eip" "nat" {
  count  = var.create_vpc ? 1 : 0
  domain = "vpc"

  tags = { Name = "npm-quarantine-nat-eip-${var.environment}" }
}

resource "aws_nat_gateway" "main" {
  count         = var.create_vpc ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id  # NAT GW fica na subnet pública

  depends_on = [aws_internet_gateway.main]
  tags       = { Name = "npm-quarantine-nat-${var.environment}" }
}

# ── Route Tables ──────────────────────────────────────────────────────────────
resource "aws_route_table" "public" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }

  tags = { Name = "npm-quarantine-rtb-public-${var.environment}" }
}

resource "aws_route_table" "private" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[0].id  # via NAT → acessa osv.dev
  }

  tags = { Name = "npm-quarantine-rtb-private-${var.environment}" }
}

resource "aws_route_table_association" "public" {
  count          = var.create_vpc ? 2 : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table_association" "private" {
  count          = var.create_vpc ? 2 : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# ── Security Group da Lambda ──────────────────────────────────────────────────
resource "aws_security_group" "lambda" {
  count       = var.create_vpc ? 1 : 0
  name        = "npm-quarantine-lambda-sg-${var.environment}"
  description = "Lambda npm-quarantine: HTTPS saída apenas"
  vpc_id      = aws_vpc.main[0].id

  # Egress: HTTPS para internet (osv.dev) e VPC Endpoints
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS saída para osv.dev e endpoints AWS"
  }

  # Nenhum ingress — Lambda não recebe conexões
  tags = { Name = "npm-quarantine-lambda-sg-${var.environment}" }
}

# Security Group dos VPC Endpoints
resource "aws_security_group" "vpce" {
  count       = var.create_vpc ? 1 : 0
  name        = "npm-quarantine-vpce-sg-${var.environment}"
  description = "VPC Endpoints do npm-quarantine"
  vpc_id      = aws_vpc.main[0].id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda[0].id]
    description     = "HTTPS da Lambda"
  }

  tags = { Name = "npm-quarantine-vpce-sg-${var.environment}" }
}

# ── VPC Endpoints (sem tráfego pela internet para APIs AWS) ───────────────────
locals {
  vpce_services = var.create_vpc ? [
    "codeartifact.api",
    "codeartifact.repositories",
    "sns",
    "sqs",
    "logs",
    "xray",
    "monitoring",  # CloudWatch metrics (emit_metric)
  ] : []
}

resource "aws_vpc_endpoint" "aws_services" {
  for_each = toset(local.vpce_services)

  vpc_id              = aws_vpc.main[0].id
  service_name        = "com.amazonaws.${local.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpce[0].id]
  private_dns_enabled = true

  tags = { Name = "npm-quarantine-vpce-${each.key}-${var.environment}" }
}
