
from __future__ import annotations

import datetime
import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.exceptions import ClientError

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _log(level: str, event: str, **kwargs: Any) -> None:
    """Emite log em JSON estruturado — queryável via CloudWatch Insights."""
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "level": level.upper(),
        "event": event,
        "environment": ENVIRONMENT,
        **kwargs,
    }
    getattr(logger, level)(json.dumps(record, default=str))


# ── Clientes AWS ──────────────────────────────────────────────────────────────
codeartifact = boto3.client("codeartifact")
sns_client = boto3.client("sns")
cloudwatch = boto3.client("cloudwatch")

# ── Config ────────────────────────────────────────────────────────────────────
DOMAIN = os.environ["DOMAIN"]
SOURCE_REPO = os.environ["SOURCE_REPO"]
DEST_REPO = os.environ["DEST_REPO"]
QUARANTINE_DAYS = int(os.environ["QUARANTINE_DAYS"])
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "")

# ── Config do scanner OSV.dev ─────────────────────────────────────────────────
OSV_ENABLED = os.environ.get("OSV_ENABLED", "true").lower() == "true"
# IMPORTANTE: fail-closed é o padrão seguro.
# Se OSV_FAIL_OPEN=false e o scanner falhar → pacote NÃO é promovido.
# Só defina OSV_FAIL_OPEN=true se entender e aceitar o risco de promoção sem scan.
OSV_FAIL_OPEN = os.environ.get("OSV_FAIL_OPEN", "false").lower() == "true"
OSV_TIMEOUT = int(os.environ.get("OSV_TIMEOUT", "10"))
OSV_MAX_RETRIES = int(os.environ.get("OSV_MAX_RETRIES", "3"))
CUSTOM_METRICS_ENABLED = os.environ.get("CUSTOM_METRICS_ENABLED", "true").lower() == "true"

OSV_API_URL = "https://api.osv.dev/v1/query"


@dataclass
class PackageResult:
    promoted: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "promoted": self.promoted,
            "blocked": self.blocked,
            "skipped_immature": self.skipped,
            "errors": self.errors,
            "summary": {
                "total_promoted": len(self.promoted),
                "total_blocked": len(self.blocked),
                "total_skipped": len(self.skipped),
                "total_errors": len(self.errors),
            },
        }


# ── Paginação genérica ─────────────────────────────────────────────────────────
def paginate(method: Any, result_key: str, **kwargs: Any) -> list[dict]:
    """Itera sobre todas as páginas de uma API CodeArtifact automaticamente."""
    items: list[dict] = []
    next_token: str | None = None
    while True:
        if next_token:
            kwargs["nextToken"] = next_token
        response = method(**kwargs)
        items.extend(response.get(result_key, []))
        next_token = response.get("nextToken")
        if not next_token:
            break
    return items


# ── Métricas customizadas ─────────────────────────────────────────────────────
def emit_metric(name: str, value: float, unit: str = "Count") -> None:
    """Emite métrica no namespace NPMQuarantine do CloudWatch."""
    if not CUSTOM_METRICS_ENABLED:
        return
    try:
        cloudwatch.put_metric_data(
            Namespace="NPMQuarantine",
            MetricData=[{
                "MetricName": name,
                "Value": value,
                "Unit": unit,
                "Dimensions": [{"Name": "Environment", "Value": ENVIRONMENT}],
            }],
        )
    except Exception as exc:  # noqa: BLE001
        _log("warning", "metric_emit_failed", metric=name, error=str(exc))


# ── OSV.dev — verificação real de vulnerabilidades ───────────────────────────
def check_osv_vulnerabilities(package_name: str, version: str) -> tuple[bool, list[str]]:
    """
    Consulta a API osv.dev por vulnerabilidades do pacote npm.

    OSV (Open Source Vulnerabilities) é mantido pelo Google Security Team,
    gratuito, sem necessidade de API key, e atualizado diariamente com dados
    do GitHub Advisory Database, NVD/CVE, e outras fontes.

    Comportamento em falha (todos os retries esgotados):
      OSV_FAIL_OPEN=false (padrão) → retorna (True, ["OSV_UNAVAILABLE"])
        → pacote tratado como vulnerável → NÃO é promovido (FAIL-CLOSED)
      OSV_FAIL_OPEN=true            → retorna (False, []) → promove sem scan

    Returns:
      (has_vulnerability, vuln_ids): tuple com bool e lista de IDs (CVE/GHSA/etc)
    """
    if not OSV_ENABLED:
        return False, []

    payload = json.dumps({
        "version": version,
        "package": {"name": package_name, "ecosystem": "npm"},
    }).encode("utf-8")

    last_error: BaseException | None = None

    for attempt in range(OSV_MAX_RETRIES):
        if attempt > 0:
            backoff = 2 ** attempt  # 2s, 4s, ...
            _log("info", "osv_retry",
                 package=package_name, version=version,
                 attempt=attempt, backoff_seconds=backoff)
            time.sleep(backoff)

        try:
            t0 = time.monotonic()
            req = urllib.request.Request(
                OSV_API_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
                data = json.loads(resp.read())

            latency_ms = (time.monotonic() - t0) * 1000
            emit_metric("OSVQueryLatencyMs", latency_ms, unit="Milliseconds")

            vulns: list[dict] = data.get("vulns", [])
            vuln_ids: list[str] = [v.get("id", "") for v in vulns if v.get("id")]

            if vulns:
                _log("warning", "osv_vulnerabilities_found",
                     package=package_name, version=version,
                     vuln_count=len(vulns), vuln_ids=vuln_ids)
            else:
                _log("debug", "osv_clean", package=package_name, version=version)

            return len(vulns) > 0, vuln_ids

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            _log("warning", "osv_request_failed",
                 package=package_name, version=version,
                 attempt=attempt + 1, max_retries=OSV_MAX_RETRIES,
                 error=str(exc))

    # ── Todos os retries esgotados ────────────────────────────────────────────
    emit_metric("OSVUnavailableCount", 1)

    if not OSV_FAIL_OPEN:
        _log("critical", "osv_fail_closed",
             package=package_name, version=version,
             error=str(last_error),
             action="blocking_promotion_by_policy",
             remediation="Verifique conectividade de rede e tente novamente. "
                         "Para bypass temporário (NÃO recomendado): OSV_FAIL_OPEN=true")
        return True, ["OSV_UNAVAILABLE"]

    _log("error", "osv_fail_open_override",
         package=package_name, version=version,
         warning="RISCO: pacote promovido sem verificação de CVE")
    return False, []


# ── Idempotência ──────────────────────────────────────────────────────────────
def get_versions_in_dest(package_name: str, namespace: str) -> set[str]:
    """
    Retorna conjunto de versões já presentes no DEST_REPO.
    Garante idempotência: versões já promovidas são ignoradas em re-execuções.
    """
    kwargs: dict[str, Any] = {
        "domain": DOMAIN,
        "repository": DEST_REPO,
        "format": "npm",
        "package": package_name,
    }
    if namespace:
        kwargs["namespace"] = namespace

    try:
        versions = paginate(codeartifact.list_package_versions, "versions", **kwargs)
        return {v["version"] for v in versions}
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return set()  # pacote ainda não existe no destino
        raise


# ── Bloqueio ──────────────────────────────────────────────────────────────────
def block_package(package_name: str, version: str, namespace: str, vuln_ids: list[str]) -> None:
    """Bloqueia publicação e upstream do pacote no repositório de quarentena."""
    kwargs: dict[str, Any] = {
        "domain": DOMAIN,
        "repository": SOURCE_REPO,
        "format": "npm",
        "package": package_name,
        "restrictions": {"publish": "BLOCK", "upstream": "BLOCK"},
    }
    if namespace:
        kwargs["namespace"] = namespace

    codeartifact.put_package_origin_configuration(**kwargs)
    _log("warning", "package_blocked",
         package=package_name, version=version,
         namespace=namespace or None, vuln_ids=vuln_ids,
         action="put_package_origin_configuration_block")


# ── Promoção ──────────────────────────────────────────────────────────────────
def promote_package_version(package_name: str, version: str, namespace: str) -> None:
    """Copia o pacote da quarentena para o repositório de produção."""
    kwargs: dict[str, Any] = {
        "domain": DOMAIN,
        "sourceRepository": SOURCE_REPO,
        "destinationRepository": DEST_REPO,
        "format": "npm",
        "package": package_name,
        "versions": [version],
        "allowOverwrite": False,
    }
    if namespace:
        kwargs["namespace"] = namespace

    codeartifact.copy_package_versions(**kwargs)
    _log("info", "package_promoted",
         package=package_name, version=version,
         namespace=namespace or None,
         source=SOURCE_REPO, destination=DEST_REPO)


# ── Alerta SNS ────────────────────────────────────────────────────────────────
def send_block_alert(blocked_packages: list[dict]) -> None:
    """Publica alerta SNS agregado (uma mensagem por execução, não por pacote)."""
    if not blocked_packages:
        return

    lines = "\n".join(
        f"  - {p['package']}@{p['version']} "
        f"| IDs: {', '.join(p['vuln_ids']) or 'OSV_UNAVAILABLE (fail-closed)'}"
        for p in blocked_packages
    )
    message = (
        f"🚨 [npm-quarantine/{ENVIRONMENT}] {len(blocked_packages)} pacote(s) bloqueado(s)\n\n"
        f"{lines}\n\n"
        f"Scanner: OSV.dev (https://osv.dev)\n"
        f"Ação: put_package_origin_configuration BLOCK em '{SOURCE_REPO}'\n"
        f"Domínio: {DOMAIN} | Conta: {AWS_ACCOUNT_ID}\n"
        f"Ver detalhes em CloudWatch Logs: /aws/lambda/promote-quarantined-packages-{ENVIRONMENT}"
    )

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[npm-quarantine/{ENVIRONMENT}] {len(blocked_packages)} pacote(s) bloqueado(s)",
        Message=message,
    )
    _log("info", "block_alert_sent", blocked_count=len(blocked_packages))


# ── Handler ───────────────────────────────────────────────────────────────────
def handler(event: dict, context: Any) -> dict:
    start_time = time.monotonic()
    _log("info", "execution_started",
         domain=DOMAIN, source_repo=SOURCE_REPO, dest_repo=DEST_REPO,
         quarantine_days=QUARANTINE_DAYS, osv_enabled=OSV_ENABLED,
         osv_fail_open=OSV_FAIL_OPEN)

    result = PackageResult()
    blocked_details: list[dict] = []

    # ── 1. Lista todos os pacotes na quarentena ───────────────────────────────
    try:
        packages = paginate(
            codeartifact.list_packages,
            "packages",
            domain=DOMAIN,
            repository=SOURCE_REPO,
            format="npm",
        )
    except ClientError as exc:
        _log("error", "list_packages_failed", error=str(exc))
        raise

    _log("info", "packages_discovered", total=len(packages))
    emit_metric("QuarantineQueueDepth", len(packages))
    now = datetime.datetime.now(datetime.timezone.utc)

    for pkg in packages:
        package_name: str = pkg["package"]
        namespace: str = pkg.get("namespace", "")

        try:
            versions = paginate(
                codeartifact.list_package_versions,
                "versions",
                domain=DOMAIN,
                repository=SOURCE_REPO,
                format="npm",
                package=package_name,
                **({"namespace": namespace} if namespace else {}),
                status="Published",
            )
        except ClientError as exc:
            _log("error", "list_versions_failed",
                 package=package_name, error=str(exc))
            result.errors.append(f"{package_name}: {exc}")
            continue

        # ── 2. Idempotência: descobre versões já promovidas ───────────────────
        try:
            already_in_dest = get_versions_in_dest(package_name, namespace)
            if already_in_dest:
                _log("debug", "versions_already_promoted",
                     package=package_name, already_promoted=list(already_in_dest))
        except ClientError as exc:
            _log("warning", "idempotency_check_failed",
                 package=package_name, error=str(exc),
                 fallback="continuing without idempotency guard")
            already_in_dest = set()

        for v in versions:
            version: str = v["version"]
            ns_prefix = f"@{namespace}/" if namespace else ""
            pkg_ref = f"{ns_prefix}{package_name}@{version}"

            # ── Idempotência ──────────────────────────────────────────────────
            if version in already_in_dest:
                _log("debug", "skipping_already_promoted", package_ref=pkg_ref)
                continue

            try:
                details = codeartifact.describe_package_version(
                    domain=DOMAIN,
                    repository=SOURCE_REPO,
                    format="npm",
                    package=package_name,
                    packageVersion=version,
                    **({"namespace": namespace} if namespace else {}),
                )["packageVersion"]

                published_at: datetime.datetime | None = details.get("publishedTime")
                if not published_at:
                    _log("warning", "published_time_missing", package_ref=pkg_ref)
                    continue

                age_days = (now - published_at).days

                # ── Quarentena ainda ativa ────────────────────────────────────
                if age_days < QUARANTINE_DAYS:
                    _log("info", "quarantine_active",
                         package_ref=pkg_ref, age_days=age_days,
                         required_days=QUARANTINE_DAYS,
                         remaining_days=QUARANTINE_DAYS - age_days)
                    result.skipped.append(pkg_ref)
                    continue

                # ── Scan de vulnerabilidade (OSV.dev) ─────────────────────────
                has_vuln, vuln_ids = check_osv_vulnerabilities(package_name, version)

                if has_vuln:
                    block_package(package_name, version, namespace, vuln_ids)
                    result.blocked.append(pkg_ref)
                    blocked_details.append({
                        "package": package_name,
                        "version": version,
                        "vuln_ids": vuln_ids,
                    })
                    emit_metric("PackagesBlocked", 1)
                else:
                    promote_package_version(package_name, version, namespace)
                    result.promoted.append(pkg_ref)
                    emit_metric("PackagesPromoted", 1)

            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    _log("warning", "package_not_found", package_ref=pkg_ref)
                else:
                    _log("error", "package_processing_error",
                         package_ref=pkg_ref, error_code=code, error=str(exc))
                    result.errors.append(f"{pkg_ref}: {exc}")
                continue

    # ── 3. Alerta SNS agregado ────────────────────────────────────────────────
    if blocked_details:
        try:
            send_block_alert(blocked_details)
        except ClientError as exc:
            _log("error", "sns_alert_failed", error=str(exc))

    # ── 4. Métricas de execução ───────────────────────────────────────────────
    elapsed_ms = (time.monotonic() - start_time) * 1000
    emit_metric("ExecutionDurationMs", elapsed_ms, unit="Milliseconds")
    emit_metric("ExecutionErrors", len(result.errors))

    summary = result.to_dict()
    _log("info", "execution_completed",
         elapsed_ms=round(elapsed_ms, 1), **summary["summary"])

    return summary
