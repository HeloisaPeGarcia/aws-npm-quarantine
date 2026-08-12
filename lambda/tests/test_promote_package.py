from __future__ import annotations

import datetime
import json
import os
import sys
from unittest.mock import MagicMock, call, patch
from urllib.error import URLError

import pytest

# ── Env vars antes do import ──────────────────────────────────────────────────
os.environ.setdefault("DOMAIN", "test-domain")
os.environ.setdefault("SOURCE_REPO", "npm-public-proxy")
os.environ.setdefault("DEST_REPO", "npm-store")
os.environ.setdefault("QUARANTINE_DAYS", "5")
os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test-topic")
os.environ.setdefault("OSV_ENABLED", "true")
os.environ.setdefault("OSV_FAIL_OPEN", "false")   # fail-closed por padrão nos testes
os.environ.setdefault("OSV_TIMEOUT", "5")
os.environ.setdefault("OSV_MAX_RETRIES", "2")     # menos retries nos testes
os.environ.setdefault("CUSTOM_METRICS_ENABLED", "false")  # desabilita métricas nos testes
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("AWS_ACCOUNT_ID", "123456789012")

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import promote_package as pm  # noqa: E402

# ── Fixtures ──────────────────────────────────────────────────────────────────
NOW = datetime.datetime(2024, 6, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
OLD_DATE = NOW - datetime.timedelta(days=10)  # elegível para promoção
NEW_DATE = NOW - datetime.timedelta(days=2)   # ainda em quarentena
EDGE_DATE = NOW - datetime.timedelta(days=5)  # exatamente no limite (elegível)


def make_pkg(name: str, namespace: str = "") -> dict:
    return {"package": name, "namespace": namespace}


def make_ver(ver: str) -> dict:
    return {"version": ver, "status": "Published"}


def make_details(published_at: datetime.datetime) -> dict:
    return {"packageVersion": {"publishedTime": published_at}}


def make_client_error(code: str) -> Exception:
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code, "Message": code}}, "TestOp")


# ── Testes: paginate ──────────────────────────────────────────────────────────

def test_paginate_single_page():
    mock = MagicMock(return_value={"packages": [{"package": "lodash"}]})
    result = pm.paginate(mock, "packages", domain="d", repository="r", format="npm")
    assert result == [{"package": "lodash"}]
    mock.assert_called_once()


def test_paginate_multiple_pages():
    mock = MagicMock(side_effect=[
        {"packages": [{"package": "a"}], "nextToken": "tok1"},
        {"packages": [{"package": "b"}], "nextToken": "tok2"},
        {"packages": [{"package": "c"}]},
    ])
    result = pm.paginate(mock, "packages", domain="d")
    assert len(result) == 3
    assert mock.call_count == 3


def test_paginate_empty_result():
    mock = MagicMock(return_value={"packages": []})
    result = pm.paginate(mock, "packages", domain="d")
    assert result == []


# ── Testes: check_osv_vulnerabilities ─────────────────────────────────────────

@patch("urllib.request.urlopen")
def test_osv_clean_package(mock_urlopen):
    mock_urlopen.return_value.__enter__ = MagicMock(
        return_value=MagicMock(read=MagicMock(return_value=b'{"vulns": []}'))
    )
    mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

    has_vuln, ids = pm.check_osv_vulnerabilities("lodash", "4.17.21")
    assert has_vuln is False
    assert ids == []


@patch("urllib.request.urlopen")
def test_osv_vulnerable_package(mock_urlopen):
    body = json.dumps({"vulns": [
        {"id": "CVE-2021-23337", "summary": "Prototype pollution"},
        {"id": "GHSA-jf85-cpcp-j695", "summary": "Command injection"},
    ]}).encode()
    mock_urlopen.return_value.__enter__ = MagicMock(
        return_value=MagicMock(read=MagicMock(return_value=body))
    )
    mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

    has_vuln, ids = pm.check_osv_vulnerabilities("lodash", "4.17.20")
    assert has_vuln is True
    assert "CVE-2021-23337" in ids
    assert "GHSA-jf85-cpcp-j695" in ids


@patch("promote_package.OSV_ENABLED", False)
@patch("urllib.request.urlopen")
def test_osv_disabled_skips_call(mock_urlopen):
    has_vuln, ids = pm.check_osv_vulnerabilities("any", "1.0")
    mock_urlopen.assert_not_called()
    assert has_vuln is False


@patch("promote_package.OSV_FAIL_OPEN", False)
@patch("promote_package.OSV_MAX_RETRIES", 1)
@patch("promote_package.time")
@patch("urllib.request.urlopen")
def test_osv_unavailable_fail_closed(mock_urlopen, mock_time):
    """Quando OSV falha e fail_open=False, deve retornar True (bloqueador)."""
    mock_urlopen.side_effect = URLError("connection refused")

    has_vuln, ids = pm.check_osv_vulnerabilities("pkg", "1.0.0")
    assert has_vuln is True
    assert ids == ["OSV_UNAVAILABLE"]


@patch("promote_package.OSV_FAIL_OPEN", True)
@patch("promote_package.OSV_MAX_RETRIES", 1)
@patch("promote_package.time")
@patch("urllib.request.urlopen")
def test_osv_unavailable_fail_open(mock_urlopen, mock_time):
    """Quando OSV falha e fail_open=True, promove mesmo sem scan."""
    mock_urlopen.side_effect = URLError("connection refused")

    has_vuln, ids = pm.check_osv_vulnerabilities("pkg", "1.0.0")
    assert has_vuln is False
    assert ids == []


@patch("promote_package.OSV_MAX_RETRIES", 3)
@patch("promote_package.OSV_FAIL_OPEN", False)
@patch("promote_package.time")
@patch("urllib.request.urlopen")
def test_osv_retry_then_success(mock_urlopen, mock_time):
    """Falha nas 2 primeiras tentativas, sucesso na 3a."""
    success_body = json.dumps({"vulns": []}).encode()
    success_ctx = MagicMock()
    success_ctx.__enter__ = MagicMock(
        return_value=MagicMock(read=MagicMock(return_value=success_body))
    )
    success_ctx.__exit__ = MagicMock(return_value=False)

    mock_urlopen.side_effect = [
        URLError("timeout"),
        URLError("timeout"),
        success_ctx,
    ]

    has_vuln, ids = pm.check_osv_vulnerabilities("pkg", "1.0.0")
    assert has_vuln is False
    assert mock_urlopen.call_count == 3


# ── Testes: get_versions_in_dest ─────────────────────────────────────────────

@patch.object(pm, "codeartifact")
def test_get_versions_in_dest_returns_set(mock_ca):
    mock_ca.list_package_versions.return_value = {
        "versions": [{"version": "1.0.0"}, {"version": "2.0.0"}]
    }
    result = pm.get_versions_in_dest("express", "")
    assert result == {"1.0.0", "2.0.0"}


@patch.object(pm, "codeartifact")
def test_get_versions_in_dest_not_found(mock_ca):
    mock_ca.list_package_versions.side_effect = make_client_error("ResourceNotFoundException")
    result = pm.get_versions_in_dest("new-pkg", "")
    assert result == set()


@patch.object(pm, "codeartifact")
def test_get_versions_in_dest_other_error_raises(mock_ca):
    mock_ca.list_package_versions.side_effect = make_client_error("AccessDeniedException")
    with pytest.raises(Exception):
        pm.get_versions_in_dest("pkg", "")


# ── Testes: handler — cenários principais ─────────────────────────────────────

@patch.object(pm, "send_block_alert")
@patch("urllib.request.urlopen")
@patch.object(pm, "codeartifact")
@patch("promote_package.datetime")
def test_handler_promotes_old_clean_package(mock_dt, mock_ca, mock_urlopen, mock_alert):
    """Pacote old + clean deve ser promovido."""
    mock_dt.datetime.now.return_value = NOW
    mock_dt.timezone.utc = datetime.timezone.utc
    mock_dt.timedelta = datetime.timedelta

    mock_ca.list_packages.return_value = {"packages": [make_pkg("express")]}
    mock_ca.list_package_versions.return_value = {"versions": [make_ver("4.18.0")]}
    mock_ca.describe_package_version.return_value = make_details(OLD_DATE)

    # OSV clean
    body = json.dumps({"vulns": []}).encode()
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value=body)))
    ctx.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = ctx

    result = pm.handler({}, None)

    assert "express@4.18.0" in result["promoted"]
    assert result["summary"]["total_promoted"] == 1
    assert result["summary"]["total_blocked"] == 0
    mock_ca.copy_package_versions.assert_called_once()
    mock_alert.assert_not_called()


@patch.object(pm, "send_block_alert")
@patch("urllib.request.urlopen")
@patch.object(pm, "codeartifact")
@patch("promote_package.datetime")
def test_handler_blocks_vulnerable_package(mock_dt, mock_ca, mock_urlopen, mock_alert):
    """Pacote old + vulnerável deve ser bloqueado e alertar SNS."""
    mock_dt.datetime.now.return_value = NOW
    mock_dt.timezone.utc = datetime.timezone.utc
    mock_dt.timedelta = datetime.timedelta

    mock_ca.list_packages.return_value = {"packages": [make_pkg("vuln-pkg")]}
    mock_ca.list_package_versions.return_value = {"versions": [make_ver("1.0.0")]}
    mock_ca.describe_package_version.return_value = make_details(OLD_DATE)

    body = json.dumps({"vulns": [{"id": "CVE-2024-1234"}]}).encode()
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value=body)))
    ctx.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = ctx

    result = pm.handler({}, None)

    assert "vuln-pkg@1.0.0" in result["blocked"]
    mock_ca.put_package_origin_configuration.assert_called_once()
    mock_ca.copy_package_versions.assert_not_called()
    mock_alert.assert_called_once()


@patch.object(pm, "send_block_alert")
@patch("urllib.request.urlopen")
@patch.object(pm, "codeartifact")
@patch("promote_package.datetime")
def test_handler_skips_immature_package(mock_dt, mock_ca, mock_urlopen, mock_alert):
    """Pacote novo (< QUARANTINE_DAYS) deve ser pulado."""
    mock_dt.datetime.now.return_value = NOW
    mock_dt.timezone.utc = datetime.timezone.utc
    mock_dt.timedelta = datetime.timedelta

    mock_ca.list_packages.return_value = {"packages": [make_pkg("fresh-pkg")]}
    mock_ca.list_package_versions.return_value = {"versions": [make_ver("1.0.0")]}
    mock_ca.describe_package_version.return_value = make_details(NEW_DATE)

    result = pm.handler({}, None)

    assert "fresh-pkg@1.0.0" in result["skipped_immature"]
    mock_ca.copy_package_versions.assert_not_called()
    mock_urlopen.assert_not_called()  # não chama OSV se ainda em quarentena


@patch.object(pm, "send_block_alert")
@patch("urllib.request.urlopen")
@patch.object(pm, "codeartifact")
@patch("promote_package.datetime")
def test_handler_idempotency_skips_already_promoted(mock_dt, mock_ca, mock_urlopen, mock_alert):
    """Versões já no DEST_REPO devem ser silenciosamente ignoradas."""
    mock_dt.datetime.now.return_value = NOW
    mock_dt.timezone.utc = datetime.timezone.utc
    mock_dt.timedelta = datetime.timedelta

    mock_ca.list_packages.return_value = {"packages": [make_pkg("express")]}

    # SOURCE_REPO tem 1.0.0 e 2.0.0; DEST_REPO já tem 1.0.0
    def list_versions_side_effect(**kwargs):
        if kwargs.get("repository") == "npm-public-proxy":
            return {"versions": [make_ver("1.0.0"), make_ver("2.0.0")]}
        # DEST_REPO
        return {"versions": [make_ver("1.0.0")]}

    mock_ca.list_package_versions.side_effect = list_versions_side_effect
    mock_ca.describe_package_version.return_value = make_details(OLD_DATE)

    body = json.dumps({"vulns": []}).encode()
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value=body)))
    ctx.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = ctx

    result = pm.handler({}, None)

    # Só 2.0.0 deve ter sido processado e promovido
    assert "express@2.0.0" in result["promoted"]
    assert "express@1.0.0" not in result["promoted"]
    assert result["summary"]["total_promoted"] == 1
    mock_ca.copy_package_versions.assert_called_once()


@patch.object(pm, "send_block_alert")
@patch("urllib.request.urlopen")
@patch.object(pm, "codeartifact")
@patch("promote_package.datetime")
def test_handler_scoped_package_namespace(mock_dt, mock_ca, mock_urlopen, mock_alert):
    """Pacotes com namespace @scope/pkg devem funcionar corretamente."""
    mock_dt.datetime.now.return_value = NOW
    mock_dt.timezone.utc = datetime.timezone.utc
    mock_dt.timedelta = datetime.timedelta

    mock_ca.list_packages.return_value = {"packages": [make_pkg("core", namespace="angular")]}
    mock_ca.list_package_versions.return_value = {"versions": [make_ver("17.0.0")]}
    mock_ca.describe_package_version.return_value = make_details(OLD_DATE)

    body = json.dumps({"vulns": []}).encode()
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value=body)))
    ctx.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = ctx

    result = pm.handler({}, None)

    # O pkg_ref deve incluir o namespace
    assert "@angular/core@17.0.0" in result["promoted"]
    # namespace deve ser passado para copy_package_versions
    call_kwargs = mock_ca.copy_package_versions.call_args[1]
    assert call_kwargs.get("namespace") == "angular"


@patch.object(pm, "send_block_alert")
@patch.object(pm, "codeartifact")
@patch("promote_package.datetime")
def test_handler_package_without_published_time(mock_dt, mock_ca, mock_alert):
    """Pacotes sem publishedTime devem ser ignorados (sem erro)."""
    mock_dt.datetime.now.return_value = NOW
    mock_dt.timezone.utc = datetime.timezone.utc
    mock_dt.timedelta = datetime.timedelta

    mock_ca.list_packages.return_value = {"packages": [make_pkg("no-time")]}
    mock_ca.list_package_versions.return_value = {"versions": [make_ver("1.0.0")]}
    mock_ca.describe_package_version.return_value = {"packageVersion": {}}

    result = pm.handler({}, None)

    assert result["summary"]["total_promoted"] == 0
    assert result["summary"]["total_errors"] == 0


@patch.object(pm, "send_block_alert")
@patch("urllib.request.urlopen")
@patch.object(pm, "codeartifact")
@patch("promote_package.datetime")
def test_handler_sns_failure_does_not_stop_execution(mock_dt, mock_ca, mock_urlopen, mock_alert):
    """Falha no SNS não deve abortar a execução nem deixar de retornar resultado."""
    mock_dt.datetime.now.return_value = NOW
    mock_dt.timezone.utc = datetime.timezone.utc
    mock_dt.timedelta = datetime.timedelta

    mock_ca.list_packages.return_value = {"packages": [make_pkg("vuln-pkg")]}
    mock_ca.list_package_versions.return_value = {"versions": [make_ver("1.0.0")]}
    mock_ca.describe_package_version.return_value = make_details(OLD_DATE)

    # OSV encontra vulnerabilidade
    body = json.dumps({"vulns": [{"id": "CVE-X"}]}).encode()
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value=body)))
    ctx.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = ctx

    # SNS falha
    mock_alert.side_effect = make_client_error("ServiceUnavailable")

    # Handler deve continuar e retornar o resultado mesmo com SNS falhando
    result = pm.handler({}, None)

    assert result["summary"]["total_blocked"] == 1
    assert "vuln-pkg@1.0.0" in result["blocked"]


@patch.object(pm, "send_block_alert")
@patch("urllib.request.urlopen")
@patch.object(pm, "codeartifact")
@patch("promote_package.datetime")
def test_handler_resource_not_found_skips_gracefully(mock_dt, mock_ca, mock_urlopen, mock_alert):
    """ResourceNotFoundException no describe deve apenas pular, sem erro."""
    mock_dt.datetime.now.return_value = NOW
    mock_dt.timezone.utc = datetime.timezone.utc
    mock_dt.timedelta = datetime.timedelta

    mock_ca.list_packages.return_value = {"packages": [make_pkg("gone-pkg")]}
    mock_ca.list_package_versions.return_value = {"versions": [make_ver("1.0.0")]}
    mock_ca.describe_package_version.side_effect = make_client_error("ResourceNotFoundException")

    result = pm.handler({}, None)

    assert result["summary"]["total_promoted"] == 0
    assert result["summary"]["total_errors"] == 0  # ResourceNotFound não é erro


@patch.object(pm, "send_block_alert")
@patch("urllib.request.urlopen")
@patch.object(pm, "codeartifact")
@patch("promote_package.datetime")
def test_handler_mixed_scenario(mock_dt, mock_ca, mock_urlopen, mock_alert):
    """clean+old → promovido, vuln+old → bloqueado, qualquer+new → skipped."""
    mock_dt.datetime.now.return_value = NOW
    mock_dt.timezone.utc = datetime.timezone.utc
    mock_dt.timedelta = datetime.timedelta

    packages = [make_pkg("clean"), make_pkg("vuln"), make_pkg("fresh")]
    mock_ca.list_packages.return_value = {"packages": packages}

    def list_versions(**kwargs):
        return {"versions": [make_ver("1.0.0")]}

    def describe(**kwargs):
        dates = {"clean": OLD_DATE, "vuln": OLD_DATE, "fresh": NEW_DATE}
        return make_details(dates[kwargs["package"]])

    mock_ca.list_package_versions.side_effect = list_versions
    mock_ca.describe_package_version.side_effect = describe

    osv_responses = [
        json.dumps({"vulns": []}).encode(),           # clean → ok
        json.dumps({"vulns": [{"id": "CVE-X"}]}).encode(),  # vuln → bloqueado
    ]
    contexts = []
    for body in osv_responses:
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value=body)))
        ctx.__exit__ = MagicMock(return_value=False)
        contexts.append(ctx)
    mock_urlopen.side_effect = contexts

    result = pm.handler({}, None)

    assert result["summary"]["total_promoted"] == 1
    assert result["summary"]["total_blocked"] == 1
    assert result["summary"]["total_skipped"] == 1
    assert "clean@1.0.0" in result["promoted"]
    assert "vuln@1.0.0" in result["blocked"]
    assert "fresh@1.0.0" in result["skipped_immature"]
