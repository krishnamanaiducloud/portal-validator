import base64
import io
import json
import logging
import asyncio
import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.logging_config import LOGGER, log_event
from app.main import (
    Authentication,
    ScanRequest,
    app,
    auth_headers,
    browser_context_options,
    classify_page_result,
    discover_storage_profiles,
    evaluate_navigation_scope,
    headers_for_destination,
    host_in_scope,
    partition_links,
    sanitized_diagnostic,
    sanitized_url,
    storage_state_path,
    url_in_scope,
)
from app.navigation import (
    AuthenticationNavigationPolicy,
    NavigationTracker,
    classify_authentication,
    classify_navigation_error,
)
from app.reporting import aggregate_report
from app.security import (
    DestinationError,
    normalized_host,
    sanitize_data,
    validate_http_url,
    validate_resolved_addresses,
)


client = TestClient(app)


def test_home_health_and_security_headers():
    response = client.get("/")
    assert response.status_code == 200
    assert "Know your portal" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/healthz").json() == {"status": "ok", "version": "1.12.3"}


@pytest.mark.parametrize("max_pages", [5, 10, 40])
def test_async_scan_api_returns_immediately_and_exposes_progress_and_report(monkeypatch, max_pages):
    async def fake_execute(req, *, scan_id, progress_callback, cancel_event):
        await progress_callback("STARTING")
        await asyncio.sleep(0.02)
        await progress_callback(
            "VALIDATING",
            discovered=max_pages + 4,
            queued=4,
            validated=max_pages,
            healthy=max_pages - 1,
            failed=1,
            warnings=0,
            current_route="https://portal.example.com/current",
        )
        return {
            "scan_id": scan_id,
            "run_id": scan_id,
            "pages": max_pages,
            "summary": {
                "scan_completeness": "PARTIAL",
                "termination_reason": "MAX_ROUTES_REACHED",
                "routes_discovered": max_pages + 4,
                "routes_validated": max_pages,
                "healthy_routes": max_pages - 1,
                "failed_pages": 1,
                "routes_with_warnings": 0,
            },
            "results": [],
        }

    monkeypatch.setattr("app.main.execute_scan", fake_execute)
    with TestClient(app) as async_client:
        started = time.perf_counter()
        created = async_client.post("/api/scans", json={
            "target": "https://portal.example.com",
            "max_pages": max_pages,
        })
        assert created.status_code == 202
        assert time.perf_counter() - started < 0.5
        scan_id = created.json()["scan_id"]
        states = []
        for _ in range(100):
            status = async_client.get(f"/api/scans/{scan_id}")
            assert status.status_code == 200
            states.append(status.json()["state"])
            if status.json()["state"] in {"PARTIAL", "COMPLETED", "FAILED"}:
                break
            time.sleep(0.01)
        assert states[-1] == "PARTIAL"
        final_status = status.json()
        assert final_status["validated"] == max_pages
        report = async_client.get(f"/api/scans/{scan_id}/report")
        assert report.status_code == 200
        assert report.json()["pages"] == max_pages


def test_async_scan_status_and_report_errors_are_json():
    response = client.get("/api/scans/not-present")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")


def test_async_scan_cancellation_finalizes_a_partial_report(monkeypatch):
    async def cancellable_execute(req, *, scan_id, progress_callback, cancel_event):
        await progress_callback("VALIDATING", discovered=3, queued=3, validated=0)
        await asyncio.wait_for(cancel_event.wait(), timeout=2)
        return {
            "scan_id": scan_id,
            "run_id": scan_id,
            "pages": 0,
            "summary": {
                "scan_completeness": "CANCELLED",
                "termination_reason": "USER_CANCELLED",
                "routes_discovered": 3,
                "routes_validated": 0,
                "healthy_routes": 0,
                "failed_pages": 0,
                "routes_with_warnings": 0,
            },
            "results": [],
        }

    monkeypatch.setattr("app.main.execute_scan", cancellable_execute)
    with TestClient(app) as async_client:
        created = async_client.post("/api/scans", json={
            "target": "https://portal.example.com",
        })
        scan_id = created.json()["scan_id"]
        cancelled = async_client.post(f"/api/scans/{scan_id}/cancel")
        assert cancelled.status_code == 202
        for _ in range(100):
            status = async_client.get(f"/api/scans/{scan_id}").json()
            if status["state"] == "CANCELLED":
                break
            time.sleep(0.01)
        assert status["state"] == "CANCELLED"
        report = async_client.get(f"/api/scans/{scan_id}/report").json()
        assert report["summary"]["termination_reason"] == "USER_CANCELLED"


@pytest.mark.parametrize(("candidate", "root", "subdomains", "expected"), [
    ("example.com", "example.com", False, True),
    ("www.example.com", "example.com", False, True),
    ("example.com", "www.example.com", False, True),
    ("api.example.com", "example.com", False, False),
    ("api.example.com", "example.com", True, True),
    ("EXAMPLE.COM.", "example.com", False, True),
    ("example.com.evil.com", "example.com", True, False),
    ("evilexample.com", "example.com", True, False),
    ("notexample.com", "example.com", True, False),
    ("example.co.uk", "co.uk", True, False),
])
def test_crawler_host_scope(candidate, root, subdomains, expected):
    assert host_in_scope(candidate, root, subdomains) is expected


def test_url_normalization_and_scope():
    assert normalized_host(" EXAMPLE.COM. ") == "example.com"
    assert url_in_scope("https://example.com:443/page", "www.example.com", False)
    assert url_in_scope("http://www.example.com:8080/page", "example.com", False)
    assert not url_in_scope("file:///etc/passwd", "example.com", False)
    assert evaluate_navigation_scope(
        "https://google.com", "https://www.google.com/", "google.com", False,
    ) == ("google.com", "www.google.com", True)


@pytest.mark.parametrize(("target", "expected"), [
    ("google.com", "https://google.com"),
    ("www.google.com", "https://www.google.com"),
    ("//google.com/path", "https://google.com/path"),
    ("https://google.com", "https://google.com"),
    ("http://google.com", "http://google.com"),
])
def test_target_input_normalization(target, expected):
    assert ScanRequest(target=target).target == expected


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://example.com/file", "https://user:secret@example.com",
    "https://example.com:22", "https://example.com:bad",
])
def test_unsafe_urls_are_rejected(url):
    with pytest.raises(DestinationError):
        validate_http_url(url)


def test_ssrf_address_policy():
    assert validate_resolved_addresses({"93.184.216.34"}, False) == ["93.184.216.34"]
    assert validate_resolved_addresses({"10.0.0.8"}, True) == ["10.0.0.8"]
    for address in ("127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1"):
        with pytest.raises(DestinationError):
            validate_resolved_addresses({address}, True)
    with pytest.raises(DestinationError, match="explicit approval"):
        validate_resolved_addresses({"10.0.0.8"}, False)


def test_cross_origin_sso_redirect_chain_is_recorded_but_not_crawled():
    tracker = NavigationTracker(max_redirects=5)
    tracker.record_destination("https://portal.example.com", now=1.0)
    tracker.record_response("https://portal.example.com", 302)
    tracker.record_destination("https://identity.example.net/login?state=secret", now=1.1)
    tracker.record_response("https://identity.example.net/login?state=secret", 302)
    tracker.record_destination("https://portal.example.com/callback?code=secret", now=1.2)
    redirects = tracker.redirects()
    assert tracker.redirect_count == 2
    assert [item["redirect_type"] for item in redirects] == ["CROSS_ORIGIN", "CROSS_ORIGIN"]
    assert "secret" not in str(redirects)
    crawl, external = partition_links(
        ["https://portal.example.com/home", "https://identity.example.net/profile"],
        "portal.example.com",
        False,
    )
    assert crawl == ["https://portal.example.com/home"]
    assert external == ["https://identity.example.net/profile"]


def test_authentication_navigation_allows_generic_oauth_saml_chain():
    policy = AuthenticationNavigationPolicy(approved_hosts=frozenset({"federation.example.org"}))
    assert policy.allows_main_frame_method("GET", "https://portal.example.com")
    assert policy.allows_main_frame_method(
        "GET",
        "https://identity.example.net/oauth2/authorize?client_id=portal&state=secret",
    )
    assert policy.active
    assert policy.allows_main_frame_method(
        "POST",
        "https://federation.example.org/idp/SSO.saml2",
        "SAMLRequest=secret&RelayState=secret",
    )
    assert policy.allows_main_frame_method(
        "GET", "https://portal.example.com/oauth/callback?code=secret&state=secret",
    )
    assert not AuthenticationNavigationPolicy().allows_main_frame_method(
        "POST", "https://unrelated.example.net/change", "action=delete",
    )
    assert not policy.allows_main_frame_method(
        "POST", "https://unrelated.example.net/change", "action=delete",
    )
    assert not policy.allows_main_frame_method(
        "DELETE", "https://identity.example.net/session", None,
    )


def test_http_redirect_chain_reconciliation_captures_google_style_redirect():
    tracker = NavigationTracker(max_redirects=5)
    tracker.record_destination("https://example.test", now=1.0)
    tracker.reconcile_http_chain([
        ("https://example.test", 301),
        ("https://www.example.test/", 200),
    ])
    redirects = tracker.redirects()
    assert tracker.redirect_count == 1
    assert redirects[0]["source_url"] == "https://example.test"
    assert redirects[0]["destination_url"] == "https://www.example.test/"
    assert redirects[0]["status"] == 301
    assert redirects[0]["same_origin"] is False


def test_redirect_limits_and_loop_detection():
    tracker = NavigationTracker(max_redirects=1)
    tracker.record_destination("https://example.com", now=1.0)
    tracker.record_destination("https://www.example.com", now=2.0)
    with pytest.raises(DestinationError, match="Maximum redirect"):
        tracker.record_destination("https://login.example.net", now=3.0)
    loop = NavigationTracker(max_redirects=4)
    loop.record_destination("https://example.com", now=1.0)
    with pytest.raises(DestinationError, match="loop"):
        loop.record_destination("https://example.com#fragment", now=2.0)

    sso_return = NavigationTracker(max_redirects=4)
    sso_return.record_destination("https://portal.example.com", now=1.0)
    sso_return.record_destination("https://identity.example.net/authorize", now=2.0)
    sso_return.record_destination(
        "https://portal.example.com", now=3.0, allow_revisit=True,
    )
    assert sso_return.redirect_count == 2
    with pytest.raises(DestinationError, match="loop"):
        sso_return.record_destination(
            "https://portal.example.com", now=4.0, allow_revisit=True,
        )


@pytest.mark.parametrize(("kwargs", "expected"), [
    ({"authentication_mode": "none", "status": 401, "final_url": "https://example.com", "target_in_scope": True, "error_classification": None}, "AUTH_REQUIRED"),
    ({"authentication_mode": "bearer", "status": 401, "final_url": "https://example.com", "target_in_scope": True, "error_classification": None}, "AUTH_FAILED"),
    ({"authentication_mode": "none", "status": 200, "final_url": "https://id.example.net/auth?client_id=x", "target_in_scope": False, "error_classification": None}, "AUTH_REQUIRED"),
    ({"authentication_mode": "storage_state", "status": 200, "final_url": "https://id.example.net/auth?client_id=x", "target_in_scope": False, "error_classification": None}, "SESSION_EXPIRED"),
    ({"authentication_mode": "none", "status": 403, "final_url": "https://example.com", "target_in_scope": True, "error_classification": None}, "ACCESS_RESTRICTED"),
])
def test_generic_authentication_classification(kwargs, expected):
    assert classify_authentication(**kwargs) == expected


def test_navigation_error_classification():
    assert classify_navigation_error("net::ERR_CERT_AUTHORITY_INVALID") == "TLS_ERROR"
    assert classify_navigation_error("net::ERR_NAME_NOT_RESOLVED") == "DNS_ERROR"
    assert classify_navigation_error("Timeout 30000ms exceeded") == "TIMEOUT"
    assert classify_navigation_error("net::ERR_CONNECTION_REFUSED") == "NETWORK_ERROR"


def test_credentials_do_not_cross_origins():
    sensitive = {"Authorization": "Bearer top-secret", "X-API-Key": "api-secret"}
    initial = {"Accept": "text/html", "authorization": "stale-secret"}
    allowed = headers_for_destination(initial, sensitive, "portal.example.com", {"portal.example.com"})
    external = headers_for_destination(initial, sensitive, "identity.example.net", {"portal.example.com"})
    assert allowed["Authorization"] == "Bearer top-secret"
    assert allowed["X-API-Key"] == "api-secret"
    assert all(name.lower() not in {"authorization", "x-api-key"} for name in external)


def test_sanitization_and_structured_log_redaction():
    secret_url = "https://user:password@example.com/path?token=secret&safe=value#fragment"
    assert sanitized_url(secret_url) == "https://example.com/path?token=%5BREDACTED%5D&safe=value"
    assert sanitized_url(
        "https://example.com/#/reports?token=secret&view=summary"
    ) == "https://example.com/#/reports?token=%5BREDACTED%5D&view=summary"
    data = sanitize_data({"authorization": "Bearer abc", "nested": {"password": "secret"}})
    assert data == {"authorization": "[REDACTED]", "nested": {"password": "[REDACTED]"}}
    old_level = LOGGER.level
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.DEBUG)
    try:
        for level in (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR):
            log_event(level, "REDACTION_TEST", url=secret_url, token="secret", authorization="Bearer abc")
    finally:
        LOGGER.setLevel(old_level)
        LOGGER.removeHandler(handler)
    output = stream.getvalue()
    assert "password" not in output
    assert "Bearer abc" not in output
    assert '"token":"secret"' not in output
    assert "[REDACTED]" in output
    for line in output.splitlines():
        assert __import__("json").loads(line)["event"] == "REDACTION_TEST"


def test_basic_auth_and_input_guards(monkeypatch):
    result = auth_headers(Authentication(mode="basic", username="user", password="secret"))
    assert result == {"Authorization": "Basic " + base64.b64encode(b"user:secret").decode()}
    with pytest.raises(ValueError):
        Authentication(mode="headers", headers={"Host": "evil.test"})
    with pytest.raises(HTTPException):
        storage_state_path("../secret")

    async def allow_destination(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.main.validate_destination", allow_destination)
    response = client.post("/api/scan", json={
        "target": "https://example.com",
        "allow_mutations": True,
        "mutation_endpoint_allowlist": ["/test/"],
    })
    assert response.status_code == 400
    assert "read-only" in response.json()["detail"]


def test_storage_profiles_are_validated_discovered_and_never_returned(monkeypatch, tmp_path):
    secret_value = "cookie-value-that-must-not-be-returned"
    valid = tmp_path / "approved.json"
    valid.write_text(json.dumps({
        "cookies": [{
            "name": "session", "value": secret_value, "domain": "portal.example.com", "path": "/",
        }],
        "origins": [{
            "origin": "https://portal.example.com",
            "localStorage": [{"name": "session-key", "value": "local-secret"}],
        }],
    }), encoding="utf-8")
    (tmp_path / "invalid.json").write_text("not-json", encoding="utf-8")
    monkeypatch.setattr("app.main.AUTH_STATE_DIR", tmp_path)
    assert discover_storage_profiles() == ["approved"]
    assert storage_state_path("approved") == valid.resolve()
    assert browser_context_options(valid)["storage_state"] == str(valid)
    assert browser_context_options(valid)["ignore_https_errors"] is False
    response = client.get("/api/auth-profiles")
    assert response.json()["profiles"] == ["approved"]
    assert secret_value not in response.text
    assert "local-secret" not in response.text
    with pytest.raises(HTTPException, match="not valid"):
        storage_state_path("invalid")


def test_page_status_distinguishes_tls_main_document_and_subresources():
    tls = classify_page_result(
        url="https://portal.example.com", status=None,
        error="Page.goto: net::ERR_CERT_AUTHORITY_INVALID",
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True,
    )
    assert (tls["page_load_status"], tls["category"], tls["tls_status"]) == (
        "FAILED_TO_LOAD", "TLS_CERTIFICATE_ERROR", "UNTRUSTED",
    )
    warning = classify_page_result(
        url="https://portal.example.com", status=200, error=None,
        missing_security_headers=[], console_errors=[],
        failed_resources=[{"main_document": False}], security_headers_tested=True,
    )
    assert warning["page_load_status"] == "LOADED"
    assert warning["validation_status"] == "WARNING"
    failed = classify_page_result(
        url="https://portal.example.com", status=None,
        error="net::ERR_NAME_NOT_RESOLVED", missing_security_headers=[],
        console_errors=[], failed_resources=[{"main_document": True}],
        security_headers_tested=True,
    )
    assert failed["page_load_status"] == "FAILED_TO_LOAD"
    assert failed["classification"] == "DNS_ERROR"


def test_clean_page_is_passed_and_browser_tls_success_is_not_a_finding():
    result = classify_page_result(
        url="https://portal.example.com", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True,
    )
    assert result["classification"] == "PASS"
    assert result["passed"] is True
    assert result["tls_status"] == "TRUSTED"
    assert result["tls_basis"] == "CHROMIUM_STRICT"
    assert result["tls"]["certificate_verification"] is True
    assert result["tls"]["bypass_used"] is False
    assert result["findings"] == 0


def test_optional_header_warning_remains_a_passed_page():
    result = classify_page_result(
        url="https://portal.example.com", status=200, error=None,
        missing_security_headers=["content-security-policy"],
        console_errors=[], failed_resources=[], security_headers_tested=True,
    )
    assert result["classification"] == "PASS_WITH_WARNINGS"
    assert result["validation_status"] == "WARNING"
    assert result["passed"] is True
    assert result["warning_findings"] == 1


def test_http_error_and_anonymous_auth_required_have_distinct_outcomes():
    server_error = classify_page_result(
        url="https://portal.example.com", status=500, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True,
    )
    assert server_error["classification"] == "HTTP_ERROR"
    assert server_error["validation_status"] == "FAIL"
    auth = classify_page_result(
        url="https://identity.example.net/authorize", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, authentication_classification="AUTH_REQUIRED",
    )
    assert auth["classification"] == "AUTH_REQUIRED"
    assert auth["page_load_status"] == "LOADED"
    assert auth["tls_status"] == "TRUSTED"
    assert auth["passed"] is False


def test_validator_generated_resource_blocks_are_info_and_deduplicated():
    failures = [{
        "url": "https://tracker.example.net/script.js",
        "error": "net::ERR_BLOCKED_BY_CLIENT",
        "resource_type": "script",
        "main_document": False,
        "blocked_by_validator": True,
        "block_reason": "third_party_resource_policy",
    }] * 17
    result = classify_page_result(
        url="https://portal.example.com", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=failures,
        security_headers_tested=True,
    )
    assert result["classification"] == "PASS"
    assert result["validation_status"] == "PASS"
    assert result["findings"] == 1
    assert result["finding_occurrences"] == 17
    assert result["info_findings"] == 1
    assert result["warning_findings"] == 0
    assert result["finding_details"][0]["blocked_by_validator"] is True


def test_report_aggregation_counts_pass_with_warnings_as_passed():
    results = []
    for index in range(25):
        result = classify_page_result(
            url=f"https://portal.example.com/{index}", status=200, error=None,
            missing_security_headers=["referrer-policy"] if index % 2 else [],
            console_errors=[], failed_resources=[], security_headers_tested=True,
        )
        result["load_ms"] = 10
        results.append(result)
    summary = aggregate_report(results)
    assert summary["total_pages"] == 25
    assert summary["loaded"] == 25
    assert summary["failed_to_load"] == 0
    assert summary["passed_pages"] == 25
    assert summary["pass_with_warnings"] == 12
    assert summary["failed_pages"] == 0


def test_auth_required_is_separate_from_failed_pages_in_aggregation():
    result = classify_page_result(
        url="https://identity.example.net/login", status=200, error=None,
        missing_security_headers=[], console_errors=[], failed_resources=[],
        security_headers_tested=True, authentication_classification="AUTH_REQUIRED",
    )
    result["load_ms"] = 5
    summary = aggregate_report([result])
    assert summary["loaded"] == 1
    assert summary["auth_required_pages"] == 1
    assert summary["failed_to_load"] == 0
    assert summary["failed_pages"] == 0


def test_production_sources_contain_no_tls_bypass():
    repository = Path(__file__).resolve().parents[1]
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [repository / "app/main.py", repository / "Dockerfile", repository / "container-entrypoint.sh"]
    )
    for forbidden in (
        "ignore_https_errors=True", "--ignore-certificate-errors",
        "verify=False", "NODE_TLS_REJECT_UNAUTHORIZED=0",
    ):
        assert forbidden not in sources


def test_portal_hosts_do_not_broaden_resource_or_credential_scope_implicitly():
    request = ScanRequest(
        target="https://portal.example.com",
        portal_hosts=["app.example.net"],
        resource_hosts=["cdn.example.org"],
    )
    assert request.portal_hosts == ["app.example.net"]
    assert request.resource_hosts == ["cdn.example.org"]
    assert request.credential_hosts == []


def test_unexpected_mutations_are_not_configurable():
    response = client.post("/api/scan", json={
        "target": "https://example.com",
        "allow_mutations": True,
        "mutation_acknowledged": True,
        "mutation_endpoint_allowlist": ["/sandbox/"],
    })
    assert response.status_code == 400
    assert "read-only" in response.json()["detail"]
