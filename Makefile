.PHONY: help test lint deploy destroy invoke logs

ENVIRONMENT ?= dev
REGION      ?= us-east-1

help: ## Mostra esta mensagem de ajuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Testes ────────────────────────────────────────────────────────────────────
test: ## Roda os testes unitários da Lambda
	cd lambda && pip install -q -r requirements-dev.txt && \
		pytest tests/ -v --tb=short

# ── Linting ───────────────────────────────────────────────────────────────────
lint: ## Roda ruff + mypy na Lambda
	cd lambda && \
		pip install -q ruff mypy boto3-stubs[codeartifact,sns,inspector2] && \
		ruff check . && \
		mypy promote_package.py --ignore-missing-imports

# ── Infraestrutura ────────────────────────────────────────────────────────────
init: ## Inicializa o Terraform
	cd infra && terraform init

plan: ## Gera o plano de execução Terraform
	cd infra && terraform plan -var="environment=$(ENVIRONMENT)"

deploy: test ## Roda os testes e aplica a infraestrutura
	cd infra && terraform apply -var="environment=$(ENVIRONMENT)" -auto-approve

destroy: ## Destroi toda a infraestrutura (cuidado!)
	@echo "⚠️  Isso vai destruir TODA a infraestrutura. Tem certeza? [y/N]" && \
		read ans && [ $${ans:-N} = y ] && \
		cd infra && terraform destroy -var="environment=$(ENVIRONMENT)" -auto-approve

# ── Lambda utilitários ────────────────────────────────────────────────────────
LAMBDA_NAME := $(shell cd infra && terraform output -raw lambda_function_name 2>/dev/null || echo "promote-quarantined-packages-$(ENVIRONMENT)")

invoke: ## Invoca a Lambda manualmente e mostra o resultado
	aws lambda invoke \
		--function-name $(LAMBDA_NAME) \
		--region $(REGION) \
		--log-type Tail \
		--cli-binary-format raw-in-base64-out \
		--payload '{}' \
		/dev/stdout | tail -c +1

logs: ## Tail dos logs da Lambda no CloudWatch
	aws logs tail /aws/lambda/$(LAMBDA_NAME) \
		--follow \
		--region $(REGION) \
		--format short

# ── NPM Login ─────────────────────────────────────────────────────────────────
npm-login: ## Configura o npm para usar o repositório interno
	$(shell cd infra && terraform output -raw npmrc_login_command 2>/dev/null)

# ── ZIP manual (caso precise empacotar sem terraform) ─────────────────────────
zip: ## Empacota o código da Lambda em ZIP
	cd lambda && zip -r promote_package.zip promote_package.py \
		--exclude "tests/*" --exclude "__pycache__/*" --exclude "*.pyc"
